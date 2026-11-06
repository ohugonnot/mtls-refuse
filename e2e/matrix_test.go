package e2e

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"github.com/ohugonnot/mtls-refuse/minica"
)

var versions = []struct {
	name string
	max  uint16
}{{"TLS1.2", tls.VersionTLS12}, {"TLS1.3", tls.VersionTLS13}}

// TestMatrix : un client légitime passe, et chaque client qui doit échouer échoue, sur les deux versions de TLS.
func TestMatrix(t *testing.T) {
	cases := []struct {
		name string
		want bool   // true = le serveur doit répondre 200
		why  string // sinon : la raison que le SERVEUR doit avoir écrite dans son journal
		cert func(e *env) *tls.Certificate
	}{
		{"certificat valide", true, "", func(e *env) *tls.Certificate {
			c, _ := must2(e.trusted.Issue(minica.LeafOptions{CommonName: "alice"}))
			return &c
		}},
		{"aucun certificat", false, "client didn't provide a certificate", func(e *env) *tls.Certificate { return nil }},
		{"certificat d'une autre autorité", false, "unknown authority", func(e *env) *tls.Certificate {
			other := must1(minica.NewCA("Autre CA"))
			c, _ := must2(other.Issue(minica.LeafOptions{CommonName: "mallory"}))
			return &c
		}},
		{"autorité jumelle : même nom de sujet, autre clé", false, "unknown authority", func(e *env) *tls.Certificate {
			twin := must1(minica.NewCA("Clients CA"))
			c, _ := must2(twin.Issue(minica.LeafOptions{CommonName: "mallory"}))
			return &c
		}},
		{"certificat expiré", false, "expired", func(e *env) *tls.Certificate {
			c, _ := must2(e.trusted.Issue(minica.LeafOptions{
				CommonName: "alice", NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-24 * time.Hour)}))
			return &c
		}},
		{"certificat pas encore valide", false, "expired", func(e *env) *tls.Certificate {
			c, _ := must2(e.trusted.Issue(minica.LeafOptions{
				CommonName: "alice", NotBefore: time.Now().Add(24 * time.Hour), NotAfter: time.Now().Add(48 * time.Hour)}))
			return &c
		}},
		{"certificat réservé aux serveurs (pas d'usage client)", false, "incompatible key usage", func(e *env) *tls.Certificate {
			c, _ := must2(e.trusted.Issue(minica.LeafOptions{
				CommonName: "alice", ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}))
			return &c
		}},
		{"certificat révoqué", false, "révoqué", func(e *env) *tls.Certificate {
			c, leaf := must2(e.trusted.Issue(minica.LeafOptions{CommonName: "alice"}))
			if err := e.loadCRL(e.trusted, 2, leaf); err != nil {
				t.Fatal(err)
			}
			return &c
		}},
	}
	for _, v := range versions {
		for _, tc := range cases {
			t.Run(v.name+"/"+tc.name, func(t *testing.T) {
				e := newEnv(t, option{})
				if err := e.loadCRL(e.trusted, 1); err != nil { // liste vide, numéro 1
					t.Fatal(err)
				}
				code, body, err := e.get(e.client(tc.cert(e), v.max, nil))
				if tc.want {
					if err != nil || code != 200 {
						t.Fatalf("attendu 200, obtenu code=%d err=%v", code, err)
					}
					return
				}
				if err == nil {
					t.Fatalf("le serveur a accepté ce client (code=%d, corps=%q)", code, body)
				}
				if !e.waitLog(tc.why) {
					t.Fatalf("client refusé, mais pas pour la raison attendue %q.\nclient : %v\nserveur : %s", tc.why, err, e.logs.String())
				}
			})
		}
	}
}
