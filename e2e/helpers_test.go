package e2e

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ohugonnot/mtls-refuse/gate"
	"github.com/ohugonnot/mtls-refuse/minica"
)

// env est un vrai serveur HTTPS sur le port 127.0.0.1, qui exige un certificat client.
type env struct {
	t        *testing.T
	trusted  *minica.CA // l'autorité des clients de confiance
	serverCA *minica.CA // l'autorité qui signe le certificat du serveur
	rev      *gate.Revocation
	srv      *httptest.Server
	logs     *syncBuf // ce que le serveur écrit quand il refuse une poignée de main
}

type syncBuf struct {
	mu sync.Mutex
	sb strings.Builder
}

func (b *syncBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sb.Write(p)
}

func (b *syncBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sb.String()
}

// waitLog attend que le journal du serveur contienne want : un refus n'est prouvé que par sa raison,
// pas par une simple erreur côté client (un client peut échouer pour une tout autre cause).
func (e *env) waitLog(want string) bool {
	for i := 0; i < 100; i++ {
		if strings.Contains(e.logs.String(), want) {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

type option struct {
	extraTrusted []*minica.CA // autorités de confiance en plus de `trusted`
	middleware   bool
}

func newEnv(t *testing.T, o option) *env {
	t.Helper()
	trusted := must1(minica.NewCA("Clients CA"))
	serverCA := must1(minica.NewCA("Server CA"))
	srvCert, _ := must2(serverCA.Issue(minica.LeafOptions{
		CommonName:  "localhost",
		DNSNames:    []string{"localhost"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}))
	roots := []*x509.Certificate{trusted.Cert}
	pool := trusted.Pool()
	for _, ca := range o.extraTrusted {
		roots = append(roots, ca.Cert)
		pool.AddCert(ca.Cert)
	}
	rev := gate.NewRevocation(roots...)
	var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "bonjour "+r.TLS.PeerCertificates[0].Subject.CommonName)
	})
	if o.middleware {
		h = gate.Middleware(rev, h)
	}
	srv := httptest.NewUnstartedServer(h)
	logs := &syncBuf{}
	srv.Config.ErrorLog = log.New(logs, "", 0)
	srv.TLS = gate.ServerConfig(srvCert, pool, rev)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &env{t: t, trusted: trusted, serverCA: serverCA, rev: rev, srv: srv, logs: logs}
}

// loadCRL signe et installe une liste de l'autorité ca, valable une heure.
func (e *env) loadCRL(ca *minica.CA, number int64, revoked ...*x509.Certificate) error {
	e.t.Helper()
	now := time.Now()
	der := must1(ca.CRL(revoked, number, now.Add(-time.Minute), now.Add(time.Hour)))
	return e.rev.Load(der)
}

// client fabrique un client HTTPS qui présente TOUJOURS cert (ou rien si nil), sans connexion persistante.
// Il passe par GetClientCertificate : avec `Certificates`, un client Go n'envoie que le certificat dont
// l'émetteur figure dans la liste des autorités que le serveur annonce, et omet les autres en silence
// (voir TestGoClientOmitsForeignCertificate). Le serveur ne verrait alors jamais le certificat à juger.
func (e *env) client(cert *tls.Certificate, maxVersion uint16, cache tls.ClientSessionCache) *http.Client {
	roots := e.serverCA.Pool()
	cfg := &tls.Config{RootCAs: roots, MaxVersion: maxVersion, ClientSessionCache: cache}
	if cert != nil {
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return cert, nil }
	}
	tr := &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}
	e.t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 5 * time.Second}
}

// url vise « localhost », le nom que porte le certificat du serveur : viser l'adresse IP ferait
// échouer TOUS les clients sur le certificat du serveur, et les refus testés ne prouveraient rien.
func (e *env) url() string { return strings.Replace(e.srv.URL, "127.0.0.1", "localhost", 1) }

// get renvoie le code HTTP et le corps, ou l'erreur de connexion.
func (e *env) get(c *http.Client) (int, string, error) {
	resp, err := c.Get(e.url())
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), err
}

func must1[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func must2[A, B any](a A, b B, err error) (A, B) {
	if err != nil {
		panic(err)
	}
	return a, b
}

func bigInt(n int64) *big.Int { return big.NewInt(n) }
