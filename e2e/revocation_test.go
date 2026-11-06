package e2e

import (
	"crypto/tls"
	"net/http"
	"testing"
	"time"

	"github.com/ohugonnot/mtls-refuse/minica"
)

// TestRevokedCertificateIsRefusedOnResumption : après une première connexion, le client reprend sa
// session sans refaire la vérification de chaîne. Seul VerifyConnection tourne alors : la révocation
// y est vérifiée. Dans VerifyPeerCertificate, la reprise passerait (voir mutations.sh).
func TestRevokedCertificateIsRefusedOnResumption(t *testing.T) {
	e := newEnv(t, option{})
	if err := e.loadCRL(e.trusted, 1); err != nil {
		t.Fatal(err)
	}
	cert, leaf := must2(e.trusted.Issue(minica.LeafOptions{CommonName: "alice"}))
	c := e.client(&cert, tls.VersionTLS13, tls.NewLRUClientSessionCache(4))

	resumed := func() (bool, error) {
		resp, err := c.Get(e.url())
		if err != nil {
			return false, err
		}
		defer resp.Body.Close()
		return resp.TLS.DidResume, nil
	}
	if r, err := resumed(); err != nil || r {
		t.Fatalf("première connexion : attendu une poignée de main complète réussie, obtenu reprise=%v err=%v", r, err)
	}
	// Témoin : sans révocation, la deuxième connexion reprend bien la session. Sans ce témoin, le test
	// pourrait réussir sans jamais avoir testé une reprise.
	if r, err := resumed(); err != nil || !r {
		t.Fatalf("deuxième connexion : attendu une reprise de session, obtenu reprise=%v err=%v", r, err)
	}
	if err := e.loadCRL(e.trusted, 2, leaf); err != nil {
		t.Fatal(err)
	}
	if _, err := resumed(); err == nil {
		t.Fatal("une connexion reprise avec un certificat révoqué a été acceptée")
	}
	if !e.waitLog("révoqué") {
		t.Fatalf("refusé, mais pas pour cause de révocation : %s", e.logs.String())
	}
}

// TestKeepAliveNeedsPerRequestCheck : une connexion longue ne refait pas de poignée de main. Sans
// vérification à chaque requête, un certificat révoqué en cours de route continue de servir.
func TestKeepAliveNeedsPerRequestCheck(t *testing.T) {
	for _, tc := range []struct {
		name       string
		middleware bool
		wantAfter  int
	}{{"sans middleware : la connexion ouverte continue de servir", false, 200}, {"avec middleware : refusé dès la requête suivante", true, 403}} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, option{middleware: tc.middleware})
			if err := e.loadCRL(e.trusted, 1); err != nil {
				t.Fatal(err)
			}
			cert, leaf := must2(e.trusted.Issue(minica.LeafOptions{CommonName: "alice"}))
			// Connexion persistante, versions fixées à TLS 1.2 pour garder une seule poignée de main.
			tr := &http.Transport{TLSClientConfig: &tls.Config{
				RootCAs: e.serverCA.Pool(), MaxVersion: tls.VersionTLS12,
				GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil },
			}}
			t.Cleanup(tr.CloseIdleConnections)
			c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
			if code, _, err := e.get(c); err != nil || code != 200 {
				t.Fatalf("avant révocation : code=%d err=%v", code, err)
			}
			if err := e.loadCRL(e.trusted, 2, leaf); err != nil {
				t.Fatal(err)
			}
			code, _, err := e.get(c)
			if err != nil || code != tc.wantAfter {
				t.Fatalf("après révocation : attendu %d, obtenu code=%d err=%v", tc.wantAfter, code, err)
			}
		})
	}
}

func TestForgedCRLIsRejectedAndChangesNothing(t *testing.T) {
	e := newEnv(t, option{})
	if err := e.loadCRL(e.trusted, 1); err != nil {
		t.Fatal(err)
	}
	cert, leaf := must2(e.trusted.Issue(minica.LeafOptions{CommonName: "alice"}))
	attacker := must1(minica.NewCA("Clients CA")) // même nom, autre clé : la liste a l'air légitime
	if err := e.loadCRL(attacker, 99, leaf); err == nil {
		t.Fatal("une liste signée par une autre clé a été acceptée")
	}
	if code, _, err := e.get(e.client(&cert, tls.VersionTLS13, nil)); err != nil || code != 200 {
		t.Fatalf("une liste falsifiée refusée ne doit rien changer : code=%d err=%v", code, err)
	}
}

func TestRolledBackCRLIsRejected(t *testing.T) {
	e := newEnv(t, option{})
	cert, leaf := must2(e.trusted.Issue(minica.LeafOptions{CommonName: "alice"}))
	if err := e.loadCRL(e.trusted, 1); err != nil {
		t.Fatal(err)
	}
	if err := e.loadCRL(e.trusted, 2, leaf); err != nil {
		t.Fatal(err)
	}
	// Un cache en amont ressert l'ancienne liste, celle qui ne révoque personne.
	if err := e.loadCRL(e.trusted, 1); err == nil {
		t.Fatal("un retour en arrière (numéro 1 après 2) a été accepté")
	}
	if _, _, err := e.get(e.client(&cert, tls.VersionTLS13, nil)); err == nil {
		t.Fatal("le certificat révoqué a été réactivé par le retour en arrière")
	}
}

func TestStaleCRLFailsClosed(t *testing.T) {
	e := newEnv(t, option{})
	cert, _ := must2(e.trusted.Issue(minica.LeafOptions{CommonName: "alice"}))
	if err := e.loadCRL(e.trusted, 1); err != nil { // valable une heure
		t.Fatal(err)
	}
	if code, _, err := e.get(e.client(&cert, tls.VersionTLS13, nil)); err != nil || code != 200 {
		t.Fatalf("liste fraîche : code=%d err=%v", code, err)
	}
	e.rev.SetClock(func() time.Time { return time.Now().Add(2 * time.Hour) })
	if _, _, err := e.get(e.client(&cert, tls.VersionTLS13, nil)); err == nil {
		t.Fatal("liste périmée : le serveur a continué d'accepter")
	}
	if !e.waitLog("périmée") {
		t.Fatalf("refusé, mais pas pour cause de liste périmée : %s", e.logs.String())
	}
}

func TestNoCRLFailsClosed(t *testing.T) {
	e := newEnv(t, option{})
	cert, _ := must2(e.trusted.Issue(minica.LeafOptions{CommonName: "alice"}))
	if _, _, err := e.get(e.client(&cert, tls.VersionTLS13, nil)); err == nil {
		t.Fatal("aucune liste chargée : le serveur a accepté")
	}
	if !e.waitLog("aucune liste") {
		t.Fatalf("refusé, mais pas pour cause d'absence de liste : %s", e.logs.String())
	}
}

// TestSameSerialInTwoAuthorities : deux autorités de confiance, même nom, qui émettent chacune un
// certificat de numéro de série 7. Révoquer le 7 de A ne doit pas révoquer le 7 de B.
func TestSameSerialInTwoAuthorities(t *testing.T) {
	b := must1(minica.NewCA("Clients CA"))
	e := newEnv(t, option{extraTrusted: []*minica.CA{b}})
	seven := bigInt(7)
	certA, leafA := must2(e.trusted.Issue(minica.LeafOptions{CommonName: "alice", Serial: seven}))
	certB, _ := must2(b.Issue(minica.LeafOptions{CommonName: "bob", Serial: seven}))
	if err := e.loadCRL(e.trusted, 1, leafA); err != nil {
		t.Fatal(err)
	}
	if err := e.loadCRL(b, 1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.get(e.client(&certA, tls.VersionTLS13, nil)); err == nil {
		t.Fatal("le 7 de A est révoqué : il devait être refusé")
	}
	if code, body, err := e.get(e.client(&certB, tls.VersionTLS13, nil)); err != nil || code != 200 {
		t.Fatalf("le 7 de B n'est pas révoqué : attendu 200, obtenu code=%d body=%q err=%v", code, body, err)
	}
}
