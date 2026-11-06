package e2e

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"github.com/ohugonnot/mtls-refuse/minica"
)

// TestGoClientOmitsForeignCertificate : avec `Certificates`, le client Go ne présente pas un certificat
// que le serveur ne pourrait pas valider d'après la liste d'autorités annoncée. Un test qui s'y prend
// ainsi croit tester « certificat d'une autre autorité » et teste « aucun certificat ».
func TestGoClientOmitsForeignCertificate(t *testing.T) {
	e := newEnv(t, option{})
	other := must1(minica.NewCA("Autre CA"))
	foreign, _ := must2(other.Issue(minica.LeafOptions{CommonName: "mallory"}))
	cfg := &tls.Config{RootCAs: e.serverCA.Pool(), Certificates: []tls.Certificate{foreign}}
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}, Timeout: 5 * time.Second}
	if _, _, err := e.get(c); err == nil {
		t.Fatal("le serveur a accepté ce client")
	}
	if !e.waitLog("client didn't provide a certificate") {
		t.Fatalf("attendu : « le client n'a fourni aucun certificat ». Journal du serveur : %s", e.logs.String())
	}
}
