package dialer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/proxy"
)

func getTrustedServer() *httptest.Server {
	return getTrustedServerWithHandler(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			// Do nothing.
		}),
	)
}

func getTrustedServerWithHandler(handler http.HandlerFunc) *httptest.Server {
	proxy := httptest.NewServer(handler)

	pin := certFingerprint(proxy.Certificate())
	TrustedAPIPins = append(TrustedAPIPins, pin)

	return proxy
}

func getSOCKS5Proxy(t *testing.T) (string, func()) {
	proxyListener, err := proxy.SOCKS5("tcp", "127.0.0.1:0", nil, proxy.Direct)
	require.NoError(t, err)

	proxyURL := proxyListener.Addr().String()

	cleanup := func() {
		proxyListener.Close()
	}

	return proxyURL, cleanup
}

func closeServer(server *httptest.Server) {
	pin := certFingerprint(server.Certificate())

	for i := range TrustedAPIPins {
		if TrustedAPIPins[i] == pin {
			TrustedAPIPins = append(TrustedAPIPins[:i], TrustedAPIPins[i:]...)
			break
		}
	}

	server.Close()
}

func TestProxyDialer_UseProxy(t *testing.T) {
	trustedProxy := getTrustedServer()
	defer closeServer(trustedProxy)
	socks5ProxyURL, cleanup := getSOCKS5Proxy(t)
	defer cleanup()

	provider := newProxyProvider(NewBasicTLSDialer(""), "", DoHProviders)
	d := NewProxyTLSDialer(NewBasicTLSDialer(""), socks5ProxyURL)
	d.proxyProvider = provider
	provider.dohLookup = func(ctx context.Context, q, p string) ([]string, error) { return []string{trustedProxy.URL}, nil }

	err := d.switchToReachableServer()
	require.NoError(t, err)
	require.Equal(t, formatAsAddress(trustedProxy.URL), d.proxyAddress)
}

func TestProxyDialer_UseProxy_MultipleTimes(t *testing.T) {
	proxy1 := getTrustedServer()
	defer closeServer(proxy1)
	proxy2 := getTrustedServer()
	defer closeServer(proxy2)
	proxy3 := getTrustedServer()
	defer closeServer(proxy3)
	socks5ProxyURL, cleanup := getSOCKS5Proxy(t)
	defer cleanup()

	provider := newProxyProvider(NewBasicTLSDialer(""), "", DoHProviders)
	d := NewProxyTLSDialer(NewBasicTLSDialer(""), socks5ProxyURL)
	d.proxyProvider = provider
	provider.dohLookup = func(ctx context.Context, q, p string) ([]string, error) { return []string{proxy1.URL}, nil }

	err := d.switchToReachableServer()
	require.NoError(t, err)
	require.Equal(t, formatAsAddress(proxy1.URL), d.proxyAddress)

	// Have to wait so as to not get rejected.
	time.Sleep(proxyLookupWait)

	provider.dohLookup = func(ctx context.Context, q, p string) ([]string, error) { return []string{proxy2.URL}, nil }
	err = d.switchToReachableServer()
	require.NoError(t, err)
	err := d.switchToReachableServer()
	require.NoError(t, err)
	require.Equal(t, formatAsAddress(trustedProxy.URL), d.proxyAddress)
}
