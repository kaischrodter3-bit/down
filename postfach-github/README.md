# Postfach: Passwortgeschützter Datei-Upload

Die Website ist statisch und kann gratis über GitHub Pages veröffentlicht werden. GitHub Pages führt jedoch keinen Servercode aus. Darum liegt das private Backend als Cloudflare Worker daneben; Dateien liegen in einem privaten R2-Bucket, Metadaten und Rate-Limits in D1. E-Mail-Benachrichtigungen laufen über Resend. Nur ein gemeinsames Zugangspasswort wird gebraucht; Registrierung, Benutzerkonten und Login per E-Mail gibt es nicht.

Die Empfängeradresse ist auf `kaischrodter3@gmail.com` voreingestellt. Dateien bis 20 MB kommen als E-Mail-Anhang. Größere Dateien bis 100 MB werden privat gespeichert und die Nachricht enthält einen signierten Download-Link, der nach 24 Stunden abläuft. Das ist erforderlich, weil E-Mail-Anbieter und Resend keine 100-MB-Anhänge zuverlässig unterstützen.

## 1. Projekt zu GitHub bringen

Lege ein neues GitHub-Repository an und lade den gesamten Inhalt dieses Projektordners dort in den Repository-Stamm hoch: `index.html`, `frontend.js`, `backend/`, `.github/`, `.gitignore` und diese README. Aktiviere Pages unter **Settings → Pages → Build and deployment → GitHub Actions**. Der mitgelieferte Workflow veröffentlicht bei jedem Push auf `main` die Website. Die Site-Adresse sieht typischerweise so aus:

- Repository-Website: `https://DEIN-NUTZER.github.io/REPOSITORY/`
- persönliches Pages-Repository `DEIN-NUTZER.github.io`: `https://DEIN-NUTZER.github.io/`

Der Workflow kann statische Dateien deployen, aber Geheimnisse kommen nicht ins Repository.

## 2. Cloudflare-Dienste einrichten

Erstelle einen Cloudflare-Account. Installiere Node.js 22 LTS und öffne PowerShell:

```powershell
cd $HOME\postfach-github\backend
npm install
npx wrangler login
npx wrangler d1 create postfach-uploads
npx wrangler r2 bucket create postfach-private-uploads
```

Der D1-Befehl gibt eine `database_id` aus. Trage sie in `backend/wrangler.toml` anstelle von `HIER-DIE-D1-DATABASE-ID-EINTRAGEN` ein. Ändere dort außerdem:

- `ALLOWED_ORIGIN`: nur der Origin deiner GitHub-Seite, ohne Repository-Pfad. Für `https://meinname.github.io/projekt/` also `https://meinname.github.io`.
- `MAIL_TO`: bereits `kaischrodter3@gmail.com`.
- `MAIL_FROM`: für echte Zustellung am besten eine Absenderadresse auf einer bei Resend verifizierten Domain.

Datenbankschema auf Cloudflare anlegen:

```powershell
npx wrangler d1 migrations apply postfach-uploads --remote
```

Der R2-Bucket ist privat und hat keinen öffentlichen Zugriff. Es gibt keine öffentliche Dateiliste oder öffentliche Dateiadresse.

## 3. Geheimnisse setzen

Resend-Konto erstellen, eine Absenderdomain verifizieren und einen API-Key erzeugen. Den Worker nicht mit Passwort/API-Key im Quelltext konfigurieren; die drei Werte ausschließlich als Cloudflare Secrets hinterlegen:

```powershell
npx wrangler secret put ACCESS_PASSWORD
npx wrangler secret put SESSION_SIGNING_KEY
npx wrangler secret put RESEND_API_KEY
```

Wrangler fordert jeden Wert interaktiv zur Eingabe auf. `ACCESS_PASSWORD` ist dein gemeinsames Passwort (lang und einzigartig wählen). `SESSION_SIGNING_KEY` muss ein eigener, zufälliger Schlüssel mit mindestens 32 Zeichen sein, z.B. lokal erzeugt mit:

```powershell
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

`RESEND_API_KEY` ist der API-Key des Resend-Kontos. `MAIL_TO`, `MAIL_FROM` und `ALLOWED_ORIGIN` sind nicht geheim und stehen in der Worker-Konfiguration. Resend muss die `MAIL_FROM`-Domain freigegeben haben. Bei der kostenlosen Sandbox-Absenderadresse `onboarding@resend.dev` kann Resend die Zustellung auf verifizierte Empfänger beschränken; verifiziere deine Domain für den regulären Betrieb.

## 4. Worker bereitstellen und verbinden

```powershell
npx wrangler deploy
```

Wrangler zeigt eine Worker-Adresse wie `https://postfach-upload.DEIN-KONTO.workers.dev`. Kopiere diese öffentliche URL in `frontend.js` anstelle von `https://CHANGE-ME.workers.dev`:

```js
const API_BASE = 'https://postfach-upload.DEIN-KONTO.workers.dev';
```

Committe diese Änderung und pushe nach `main`; GitHub Actions veröffentlicht damit die verbundene Website. `API_BASE` ist nur die öffentliche Adresse, kein Geheimnis. Öffne die GitHub-Pages-Seite, gib dein Zugangspasswort ein und teste zuerst eine kleine PDF. Dann teste den 100-MB-Grenzbereich.

## Schutzmaßnahmen und Grenzen

- Das Passwort, der HMAC-Signaturschlüssel und Resend-API-Key werden nur serverseitig als Cloudflare Secrets gespeichert.
- Passwortversuche werden pro IP über D1 begrenzt (8 Versuche je 15 Minuten); Uploads (10/Stunde) und Download-Links (30/Stunde) haben eigene Grenzen. Die API akzeptiert nur Requests vom konfigurierten Website-Origin.
- Nach erfolgreichem Passwort-Check erhält der Browser ein signiertes Bearer-Token mit 8 Stunden Laufzeit. Es liegt in `sessionStorage` des Tabs und wird beim Sperren gelöscht.
- Uploads sind auf 100.000.000 Bytes, eine Datei und die erlaubten Endungen sowie bekannte Dateisignaturen beschränkt. Der Browser-MIME-Type wird nicht als Beweis verwendet. Interne Objektpfade werden zufällig erstellt. R2 bleibt privat.
- Dateien größer als 20 MB werden nicht als Mail-Attachment dupliziert; der E-Mail-Link ist signiert und läuft nach 24 Stunden ab.
- Das ist ein gemeinsames Passwort, keine persönliche Benutzerverwaltung. Jeder, der das Passwort kennt, kann alle Uploads sehen und löschen. Gib es nur an dich selbst weiter, wähle ein langes einmaliges Passwort und rotiere es bei Verdacht mit `wrangler secret put ACCESS_PASSWORD`.
- Es ist keine Antivirus-/Malware-Prüfung enthalten. Die Dateisignaturprüfung sperrt nicht vertrauenswürdige Formate, ist aber kein Virenscanner.
- Prüfe aktuelle Cloudflare-/Resend-Free-Tier-Grenzen. R2, Worker, D1 und E-Mail-Provider haben Kontingente und Größen-/Durchsatzlimits, die sich ändern können.

## Lokale Entwicklung

`frontend.js` enthält die Worker-Adresse. In `backend`, nach `npm install` und `wrangler login`:

```powershell
npx wrangler dev
```

Für lokale Tests müssen D1-/R2-Bindings und Secrets in einer nicht eingecheckten Datei `backend/.dev.vars` bzw. einer lokalen Wrangler-Konfiguration gesetzt werden. Niemals echte Werte committen. Für die produktive Website verwende `wrangler deploy`.
