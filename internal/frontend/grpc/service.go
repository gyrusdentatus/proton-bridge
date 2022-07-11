// Copyright (c) 2022 Proton AG
//
// This file is part of Proton Mail Bridge.Bridge.
//
// Proton Mail Bridge is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Proton Mail Bridge is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Proton Mail Bridge. If not, see <https://www.gnu.org/licenses/>.

package grpc

//go:generate protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative bridge.proto

import (
	"crypto/tls"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/proton-bridge/v2/internal/bridge"
	"github.com/ProtonMail/proton-bridge/v2/internal/config/settings"
	"github.com/ProtonMail/proton-bridge/v2/internal/config/useragent"
	"github.com/ProtonMail/proton-bridge/v2/internal/events"
	"github.com/ProtonMail/proton-bridge/v2/internal/frontend/types"
	"github.com/ProtonMail/proton-bridge/v2/internal/locations"
	"github.com/ProtonMail/proton-bridge/v2/internal/updater"
	"github.com/ProtonMail/proton-bridge/v2/internal/users"
	"github.com/ProtonMail/proton-bridge/v2/pkg/keychain"
	"github.com/ProtonMail/proton-bridge/v2/pkg/listener"
	"github.com/ProtonMail/proton-bridge/v2/pkg/pmapi"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Service is the RPC service struct.
type Service struct { // nolint:structcheck
	UnimplementedBridgeServer
	grpcServer        *grpc.Server //  the gGRPC server
	listener          net.Listener
	eventStreamCh     chan *StreamEvent
	eventStreamDoneCh chan struct{}

	programName    string
	programVersion string
	panicHandler   types.PanicHandler
	locations      *locations.Locations
	settings       *settings.Settings
	eventListener  listener.Listener
	updater        types.Updater
	userAgent      *useragent.UserAgent
	bridge         types.Bridger
	restarter      types.Restarter
	showOnStartup  bool
	authClient     pmapi.Client
	auth           *pmapi.Auth
	password       []byte
	// newVersionInfo     updater.VersionInfo // TO-DO GODT-1670 Implement version check
	log                *logrus.Entry
	initializing       sync.WaitGroup
	initializationDone sync.Once
	firstTimeAutostart sync.Once
}

// NewService returns a new instance of the service.
func NewService(
	version,
	programName string,
	showOnStartup bool,
	panicHandler types.PanicHandler,
	locations *locations.Locations,
	settings *settings.Settings,
	eventListener listener.Listener,
	updater types.Updater,
	userAgent *useragent.UserAgent,
	bridge types.Bridger,
	_ types.NoEncConfirmator,
	restarter types.Restarter,

) *Service {
	s := Service{
		UnimplementedBridgeServer: UnimplementedBridgeServer{},
		programName:               programName,
		programVersion:            version,
		panicHandler:              panicHandler,
		locations:                 locations,
		settings:                  settings,
		eventListener:             eventListener,
		updater:                   updater,
		userAgent:                 userAgent,
		bridge:                    bridge,
		restarter:                 restarter,
		showOnStartup:             showOnStartup,

		log:                logrus.WithField("pkg", "grpc"),
		initializing:       sync.WaitGroup{},
		initializationDone: sync.Once{},
		firstTimeAutostart: sync.Once{},
	}

	s.userAgent.SetPlatform(runtime.GOOS) // TO-DO GODT-1672 In the previous Qt frontend, this routine used QSysInfo::PrettyProductName to return a more accurate description, e.g. "Windows 10" or "MacOS 10.12"

	cert, err := tls.X509KeyPair([]byte(serverCert), []byte(serverKey))
	if err != nil {
		s.log.WithError(err).Error("could not create key pair")
		panic(err)
	}

	s.initAutostart()

	s.grpcServer = grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})))

	RegisterBridgeServer(s.grpcServer, &s)

	s.listener, err = net.Listen("tcp", "127.0.0.1:9292") // Port should be configurable from the command-line.
	if err != nil {
		s.log.WithError(err).Error("could not create listener")
		panic(err)
	}

	return &s
}

func (s *Service) initAutostart() {
	// GODT-1507 Windows: autostart needs to be created after Qt is initialized.
	// GODT-1206: if preferences file says it should be on enable it here.

	// TO-DO GODT-1681 Autostart needs to be properly implement for gRPC approach.

	s.firstTimeAutostart.Do(func() {
		shouldAutostartBeOn := s.settings.GetBool(settings.AutostartKey)
		if s.bridge.IsFirstStart() || shouldAutostartBeOn {
			if err := s.bridge.EnableAutostart(); err != nil {
				s.log.WithField("prefs", shouldAutostartBeOn).WithError(err).Error("Failed to enable first autostart")
			}
			return
		}
	})
}

func (s *Service) Loop() error {
	defer func() {
		s.settings.SetBool(settings.FirstStartGUIKey, false)
	}()

	go func() {
		defer s.panicHandler.HandlePanic()
		s.watchEvents()
	}()

	err := s.grpcServer.Serve(s.listener)
	if err != nil {
		s.log.WithError(err).Error("error serving RPC")
		return err
	}
	return nil
}

// frontend interface functions TODO GODT-1670 Implement

func (s *Service) NotifyManualUpdate( /* update */ _ updater.VersionInfo /*canInstall */, _ bool) {}
func (s *Service) SetVersion( /* update */ updater.VersionInfo)                                   {}
func (s *Service) NotifySilentUpdateInstalled()                                                   {}
func (s *Service) NotifySilentUpdateError(error)                                                  {}
func (s *Service) WaitUntilFrontendIsReady()                                                      {}

func (s *Service) watchEvents() { // nolint:funlen
	if s.bridge.HasError(bridge.ErrLocalCacheUnavailable) {
		_ = s.SendEvent(NewCacheErrorEvent(CacheErrorType_CACHE_UNAVAILABLE_ERROR))
	}

	errorCh := s.eventListener.ProvideChannel(events.ErrorEvent)
	credentialsErrorCh := s.eventListener.ProvideChannel(events.CredentialsErrorEvent)
	noActiveKeyForRecipientCh := s.eventListener.ProvideChannel(events.NoActiveKeyForRecipientEvent)
	internetConnChangedCh := s.eventListener.ProvideChannel(events.InternetConnChangedEvent)
	secondInstanceCh := s.eventListener.ProvideChannel(events.SecondInstanceEvent)
	restartBridgeCh := s.eventListener.ProvideChannel(events.RestartBridgeEvent)
	addressChangedCh := s.eventListener.ProvideChannel(events.AddressChangedEvent)
	addressChangedLogoutCh := s.eventListener.ProvideChannel(events.AddressChangedLogoutEvent)
	logoutCh := s.eventListener.ProvideChannel(events.LogoutEvent)
	updateApplicationCh := s.eventListener.ProvideChannel(events.UpgradeApplicationEvent)
	userChangedCh := s.eventListener.ProvideChannel(events.UserRefreshEvent)
	certIssue := s.eventListener.ProvideChannel(events.TLSCertIssue)

	// we forward events to the GUI/frontend via the gRPC event stream.
	for {
		select {
		case errorDetails := <-errorCh:
			if strings.Contains(errorDetails, "IMAP failed") {
				_ = s.SendEvent(NewMailSettingsErrorEvent(MailSettingsErrorType_IMAP_PORT_ISSUE))
			}
			if strings.Contains(errorDetails, "SMTP failed") {
				_ = s.SendEvent(NewMailSettingsErrorEvent(MailSettingsErrorType_SMTP_PORT_ISSUE))
			}
		case reason := <-credentialsErrorCh:
			if reason == keychain.ErrMacKeychainRebuild.Error() {
				_ = s.SendEvent(NewKeychainRebuildKeychainEvent())
				continue
			}
			_ = s.SendEvent(NewKeychainHasNoKeychainEvent())
		case email := <-noActiveKeyForRecipientCh:
			_ = s.SendEvent(NewMailNoActiveKeyForRecipientEvent(email))
		case stat := <-internetConnChangedCh:
			if stat == events.InternetOff {
				_ = s.SendEvent(NewInternetStatusEvent(false))
			}
			if stat == events.InternetOn {
				_ = s.SendEvent(NewInternetStatusEvent(true))
			}

		case <-secondInstanceCh:
			_ = s.SendEvent(NewShowMainWindowEvent())
		case <-restartBridgeCh:
			s.restart()
		case address := <-addressChangedCh:
			_ = s.SendEvent(NewMailAddressChangeEvent(address))
		case address := <-addressChangedLogoutCh:
			_ = s.SendEvent(NewMailAddressChangeLogoutEvent(address))
		case userID := <-logoutCh:
			user, err := s.bridge.GetUser(userID)
			if err != nil {
				return
			}
			_ = s.SendEvent(NewUserDisconnectedEvent(user.Username()))
		case <-updateApplicationCh:
			s.updateForce()
		case userID := <-userChangedCh:
			_ = s.SendEvent(NewUserChangedEvent(userID))
		case <-certIssue:
			_ = s.SendEvent(NewMailApiCertIssue())
		}
	}
}

func (s *Service) loginAbort() {
	s.loginClean()
}

func (s *Service) loginClean() {
	s.auth = nil
	s.authClient = nil
	for i := range s.password {
		s.password[i] = '\x00'
	}
	s.password = s.password[0:0]
}

func (s *Service) finishLogin() {
	defer s.loginClean()

	if len(s.password) == 0 || s.auth == nil || s.authClient == nil {
		s.log.
			WithField("hasPass", len(s.password) != 0).
			WithField("hasAuth", s.auth != nil).
			WithField("hasClient", s.authClient != nil).
			Error("Finish login: authentication incomplete")

		_ = s.SendEvent(NewLoginError(LoginErrorType_TWO_PASSWORDS_ABORT, "Missing authentication, try again."))
		return
	}

	done := make(chan string)
	s.eventListener.Add(events.UserChangeDone, done)
	defer s.eventListener.Remove(events.UserChangeDone, done)

	user, err := s.bridge.FinishLogin(s.authClient, s.auth, s.password)

	if err != nil && err != users.ErrUserAlreadyConnected {
		s.log.WithError(err).Errorf("Finish login failed")
		_ = s.SendEvent(NewLoginError(LoginErrorType_TWO_PASSWORDS_ABORT, err.Error()))
		return
	}

	// The user changed should be triggered by FinishLogin, but it is not
	// guaranteed when this is going to happen. Therefor we should wait
	// until we receive the signal from userChanged function.
	s.waitForUserChangeDone(done, user.ID())

	s.log.WithField("userID", user.ID()).Debug("Login finished")
	_ = s.SendEvent(NewLoginFinishedEvent(user.ID()))

	if err == users.ErrUserAlreadyConnected {
		s.log.WithError(err).Error("User already logged in")
		_ = s.SendEvent(NewLoginAlreadyLoggedInEvent(user.ID()))
	}
}

func (s *Service) waitForUserChangeDone(done <-chan string, userID string) {
	for {
		select {
		case changedID := <-done:
			if changedID == userID {
				return
			}
		case <-time.After(2 * time.Second):
			s.log.WithField("ID", userID).Warning("Login finished but user not added within 2 seconds")
			return
		}
	}
}

func (s *Service) restart() {
	s.log.Error("Restart is not implemented") // TO-DO GODT-1671 implement restart.
}

func (s *Service) checkUpdate() {
	s.log.Error("checkUpdate is not implemented") // TO-DO GODT-1670 implement update check.
}

func (s *Service) updateForce() {
	s.log.Error("updateForce is not implemented") // TO-DO GODT-1670 implement update.
}

func (s *Service) checkUpdateAndNotify() {
	s.log.Error("checkUpdateAndNotify is not implemented") // TO-DO GODT-1670 implement update check.
}