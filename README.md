# mtls-refuse

**FR** · [EN below](#english)

Un serveur HTTPS Go qui exige un certificat client (mTLS), une mini-autorité de certification en bibliothèque standard, et une matrice de tests de bout en bout qui prouvent que **chaque mauvais client est refusé, et pour la bonne raison**. Le dépôt accompagne un article de web-developpeur.com sur le sujet.

Go vérifie pour toi la chaîne de confiance, les dates et l'usage « client » du certificat. Il ne regarde **jamais** une liste de révocation, et ne te dit pas pourquoi un test de refus passe. Ce dépôt écrit la pièce qui manque (`gate/`) et les tests qui la tiennent.

## Lancer

Go 1.24 ou plus récent. Sans Go installé, via Docker :

```bash
docker run --rm -v "$PWD":/src -w /src golang:1.26 sh -c 'go vet ./... && go test -race -count=1 -v ./e2e && ./mutations.sh'
```

- `go test ./e2e` : un vrai serveur sur `localhost`, de vrais clients, TLS 1.2 et TLS 1.3.
- `./mutations.sh` : casse le code de dix façons, une à la fois, et vérifie que les tests rougissent.

## Ce qui est dedans

| Dossier | Rôle |
|---|---|
| `minica/` | Autorité racine, certificats feuilles aux défauts choisis (expiré, sans usage client, numéro de série imposé), listes de révocation signées et numérotées |
| `gate/` | `ServerConfig` (`RequireAndVerifyClientCert`), registre de révocation (une liste par autorité, signature vérifiée, retour en arrière refusé, liste périmée = on ferme), `Middleware` par requête |
| `e2e/` | La matrice et les tests de pièges |

## Les cinq pièges que les tests documentent

1. **Un refus peut réussir pour la mauvaise raison.** Viser `127.0.0.1` au lieu de `localhost` fait échouer tous les clients sur le certificat du *serveur* : les tests de refus passent, et ne prouvent rien. Chaque refus est donc confirmé par la raison que le **serveur** écrit dans son journal.
2. **Un client Go omet en silence un certificat étranger.** Avec `tls.Config.Certificates`, il n'envoie que le certificat dont l'émetteur figure dans la liste d'autorités annoncée par le serveur. Le test « certificat d'une autre autorité » teste alors « aucun certificat ». Les clients de test passent par `GetClientCertificate`. L'« autorité jumelle » (même nom de sujet, autre clé) est le cas qui force le serveur à vérifier une signature.
3. **En TLS 1.3, un client refusé se connecte sans erreur.** `tls.Dial` réussit, l'alerte n'arrive qu'à la première lecture. En TLS 1.2, la poignée de main échoue.
4. **`VerifyPeerCertificate` ne tourne pas sur une connexion reprise ; `VerifyConnection` si** (documentation de `crypto/tls`). Un certificat révoqué entre deux connexions repasserait par la reprise de session.
5. **Une connexion longue ne refait pas de poignée de main.** Sans vérification par requête, un certificat révoqué continue de servir.

## Registre de preuves

| Affirmation | Statut | Preuve |
|---|---|---|
| Les huit clients de la matrice (valide, sans certificat, autre autorité, autorité jumelle, expiré, pas encore valide, sans usage client, révoqué) : le valide passe, les sept autres sont refusés pour la raison attendue, en TLS 1.2 et en TLS 1.3 | Vérifié | `TestMatrix` |
| Un client Go omet un certificat dont l'émetteur n'est pas annoncé | Vérifié | `TestGoClientOmitsForeignCertificate` |
| En TLS 1.3 la poignée de main client réussit et la première lecture porte l'alerte ; en TLS 1.2 la poignée de main échoue | Vérifié | `TestTLS13RefusalArrivesAfterHandshake` |
| Un certificat révoqué est refusé sur une connexion reprise (la reprise est constatée par `DidResume` avant la révocation) | Vérifié | `TestRevokedCertificateIsRefusedOnResumption` |
| Sans middleware, une connexion ouverte continue de servir après révocation ; avec, la requête suivante reçoit 403 | Vérifié | `TestKeepAliveNeedsPerRequestCheck` (TLS 1.2, une seule poignée de main) |
| Une liste signée par une autre clé est refusée et ne change rien, même avec le nom de la bonne autorité | Vérifié | `TestForgedCRLIsRejectedAndChangesNothing` |
| Une liste plus ancienne (numéro inférieur) est refusée, le certificat reste révoqué | Vérifié | `TestRolledBackCRLIsRejected` |
| Une liste périmée, ou l'absence de liste, ferme au lieu d'ouvrir | Vérifié | `TestStaleCRLFailsClosed`, `TestNoCRLFailsClosed` |
| Révoquer le numéro de série 7 d'une autorité ne révoque pas le 7 d'une autre autorité de même nom | Vérifié | `TestSameSerialInTwoAuthorities` |
| Chacune des dix mutations est attrapée, et la révocation déplacée dans `VerifyPeerCertificate` n'est attrapée que par le test de reprise | Vérifié | `./mutations.sh`, essai du 06/11/2026 sur Go 1.24.13 et Go 1.26.10 |
| La CI GitHub Actions passe (`go vet`, `go test -race`, `./mutations.sh`) | Vérifié | exécution 42303001046 (06/11/2026) sur Go 1.24 et Go 1.26, commit `8bfec7c` ; seul `ubuntu-latest` a été essayé |
| Les tests passent sur Go 1.24.13 et Go 1.26.10 (Linux, Docker) | Vérifié | exécutions locales du 06/11/2026 |
| Les tests passent sous macOS, Windows, ou avec une autre version de Go | **Non vérifié** | |
| OCSP | **Non traité** | le dépôt ne parle pas OCSP ; `crypto/tls` ne vérifie pas de réponse OCSP pour un certificat client |
| Récupération de la liste (HTTP, annonce par un point de distribution) | **Non traité** | `Load` reçoit des octets ; la récupération et la fréquence de rechargement sont à écrire |
| Autorité intermédiaire | **Non vérifié** | `Check` prend `chaîne[1]` comme émetteur et `Load` ne connaît que les racines données : le cas « la feuille est signée directement par une racine de confiance » est le seul testé |
| Listes delta, listes indirectes, motifs de révocation | **Non traité** | ignorés |
| HTTP/2 | **Non vérifié** | le middleware lit `req.TLS`, qui existe aussi en HTTP/2, mais le serveur de test ne l'active pas |
| Reprise de session TLS 1.2 (tickets) | **Non vérifié** | seule la reprise TLS 1.3 est testée |

## Limites assumées

C'est un dépôt de démonstration et de test, pas une bibliothèque de production : pas de persistance, pas de rechargement automatique, pas de métriques. La mini-autorité n'a aucune protection de sa clé.

## Licence

MIT.

---

## English

A Go HTTPS server that requires a client certificate (mTLS), a standard-library mini certificate authority, and an end-to-end test matrix that proves **every bad client is refused, and for the right reason**. The repository goes with an article on web-developpeur.com.

Go checks the trust chain, the dates and the certificate's "client" usage for you. It **never** looks at a revocation list, and it does not tell you why a refusal test passes. This repository writes the missing piece (`gate/`) and the tests that hold it.

## Run

Go 1.24 or newer. Without Go installed, through Docker:

```bash
docker run --rm -v "$PWD":/src -w /src golang:1.26 sh -c 'go vet ./... && go test -race -count=1 -v ./e2e && ./mutations.sh'
```

- `go test ./e2e`: a real server on `localhost`, real clients, TLS 1.2 and TLS 1.3.
- `./mutations.sh`: breaks the code ten ways, one at a time, and checks that the tests turn red.

## The five traps the tests document

1. **A refusal can pass for the wrong reason.** Dialing `127.0.0.1` instead of `localhost` makes every client fail on the *server's* certificate: the refusal tests pass and prove nothing. Each refusal is therefore confirmed by the reason the **server** writes in its log.
2. **A Go client silently omits a foreign certificate.** With `tls.Config.Certificates`, it only sends a certificate whose issuer is in the authority list the server announces. The "certificate from another authority" test then tests "no certificate". The test clients use `GetClientCertificate`. The "twin authority" (same subject name, different key) is the case that forces the server to check a signature.
3. **In TLS 1.3 a refused client connects without an error.** `tls.Dial` succeeds, the alert only arrives on the first read. In TLS 1.2 the handshake fails.
4. **`VerifyPeerCertificate` does not run on a resumed connection; `VerifyConnection` does** (`crypto/tls` documentation). A certificate revoked between two connections would get through session resumption.
5. **A long-lived connection does not redo the handshake.** Without a per-request check, a revoked certificate keeps being served.

## Proof register

See the French table above: every row names the test that proves it, or says "Non vérifié" (not verified) or "Non traité" (not handled). Not covered: OCSP, fetching the list over HTTP, intermediate authorities, delta and indirect lists, HTTP/2, TLS 1.2 session tickets, other operating systems. The GitHub Actions run 42303001046 (06/11/2026, Go 1.24 and 1.26, `ubuntu-latest` only) is green.

## Licence

MIT.
