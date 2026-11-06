package e2e

import (
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ohugonnot/mtls-refuse/minica"
)

// TestTLS13RefusalArrivesAfterHandshake : en TLS 1.3, le client termine sa poignée de main avant que le
// serveur ait jugé son certificat. Un client refusé « se connecte » sans erreur, et l'alerte n'arrive
// qu'à la première lecture. En TLS 1.2, la poignée de main elle-même échoue.
func TestTLS13RefusalArrivesAfterHandshake(t *testing.T) {
	e := newEnv(t, option{})
	if err := e.loadCRL(e.trusted, 1); err != nil {
		t.Fatal(err)
	}
	expired, _ := must2(e.trusted.Issue(minica.LeafOptions{
		CommonName: "alice", NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-24 * time.Hour)}))
	addr := strings.TrimPrefix(e.srv.URL, "https://")
	_, port, _ := net.SplitHostPort(addr)

	for _, tc := range []struct {
		name          string
		max           uint16
		handshakeFail bool
	}{{"TLS1.2", tls.VersionTLS12, true}, {"TLS1.3", tls.VersionTLS13, false}} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &tls.Config{
				RootCAs: e.serverCA.Pool(), ServerName: "localhost", MaxVersion: tc.max,
				GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &expired, nil },
			}
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", "localhost:"+port, cfg)
			if tc.handshakeFail {
				if err == nil {
					conn.Close()
					t.Fatal("la poignée de main aurait dû échouer en TLS 1.2")
				}
				return
			}
			if err != nil {
				t.Fatalf("en TLS 1.3 la poignée de main côté client devrait réussir, obtenu : %v", err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")); err != nil {
				t.Logf("écriture : %v", err)
			}
			buf := make([]byte, 1)
			_, err = conn.Read(buf)
			if err == nil || !strings.Contains(err.Error(), "expired certificate") {
				t.Fatalf("la première lecture devait porter l'alerte « expired certificate », obtenu : %v", err)
			}
		})
	}
}
