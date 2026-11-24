# ida-connect

Kleiner Agent (Rust, ~1,2 MB, ein paar MB RAM) für **IDA Health**. Auf einem Gerät installiert (Raspberry Pi, Server, NAS …):

* schickt Messwerte an IDA Health: CPU (gesamt + je Kern), RAM/Swap, Last, Platten (Belegung + Durchsatz), Temperaturen,
  Lüfter, Netz je Schnittstelle. Gespeichert wird **nichts** auf dem Gerät – nur in Health.
* **Gesundheitscheck** (Op `health`): SMART von SSD/HDD/NVMe (`smartmontools` installiert das Install-Skript bei Installation und Update selbst mit), SD-/eMMC-Karte (Verschleiß wo gemeldet, Schreibmenge),
  Dateisystemfehler (read-only, ext4-Zähler, Kernel-Log) und beim Raspberry Pi Unterspannung/Drosselung (`vcgencmd get_throttled`).
* **Selbstheilung**: Regeln wie „wenn Container X down ist, Neustart“ (auch Dienste, HTTP-Adressen, Ports, eigene Befehle). Mit Bremse gegen
  Dauerschleifen (mehrere Fehlschläge in Folge, Pause, höchstens N Aktionen pro Stunde). Läuft auf dem Gerät, auch wenn Health nicht erreichbar ist.
* **Lüftersteuerung** (hwmon-PWM, z. B. Pi-5-Lüfter): pro Lüfter Auto, feste Stärke in % oder eigene Kurve (ab X °C Y %, dazwischen
  linear, wählbarer Temperaturfühler). Einstellung liegt in der Config, der Agent regelt alle 3 s; beim Beenden geht der Lüfter zurück auf Auto.
* gibt das Gerät über Health frei: **Shell als root** (wie SSH), Dateien (ansehen, bearbeiten, hoch-/herunterladen),
  **Docker-Stacks** (aktualisieren, neu starten, Logs, Compose bearbeiten), System- und Agent-Updates.
  Dasselbe können Ida und die Threads in IDA Code (`geraet_*`-Tools).
* optional: **Cloudflare Mesh** – das Gerät bekommt eine IP im Cloudflare-Netz (100.96.0.0/12), alles darauf ist über WARP erreichbar.
* lokale Seite auf **Port 1111** zum Koppeln (mit PIN).

Die Verbindung baut immer das Gerät auf (eine WebSocket-Verbindung nach außen), es braucht also keinen offenen Port
und klappt auch hinter NAT/Mobilfunk. Protokoll: [PROTOCOL.md](PROTOCOL.md).

## Installieren

```sh
curl -fsSL https://raw.githubusercontent.com/L8teNever/Ida-connect/main/install.sh | sudo sh
```

Am Ende stehen die Adresse der lokalen Seite und die PIN. Seite öffnen (`http://<gerät>:1111`), PIN eingeben,
**„Mit IDA verbinden“**: Health öffnet sich (Anmeldung über Cloudflare Zero Trust), Gerät bestätigen, fertig.

Ohne Browser auf dem Gerät: in IDA Health **„Gerät hinzufügen“** – dort steht der fertige Befehl mit Code:

```sh
curl -fsSL https://raw.githubusercontent.com/L8teNever/Ida-connect/main/install.sh | sudo sh -s -- --code abc123-def456-789abc
```

| Option | |
|---|---|
| `--server URL` | Adresse von IDA Health, z. B. `https://health.example.com` (steht im Befehl aus Health) |
| `--port N` | Port der lokalen Seite (Standard 1111) |
| `--update` | neue Version holen – einfacher: `sudo ida-connect update` |
| `--uninstall [--purge]` | entfernen; `--purge` löscht auch Kopplung und PIN |

ida-connect läuft als **Systemdienst** (`ida-connect.service`, systemd) direkt auf dem Gerät – kein Docker nötig, startet mit dem
Gerät, startet bei einem Absturz von selbst neu (nach 5 s) und ist auf 64 MB RAM begrenzt. Das Programm liegt unter
`/usr/local/bin/ida-connect`, die Konfiguration unter `/etc/ida-connect/`.

## Updates

```sh
sudo ida-connect update           # nachsehen und – falls neuer – installieren
sudo ida-connect update --check   # nur nachsehen
sudo ida-connect auto-update off  # Auto-Update aus (Standard: an, alle 6 Stunden)
```

Oder per Knopf: auf der lokalen Seite (Port 1111) unter **Updates** oder in IDA Health beim Gerät unter **System → ida-connect**.
Beim Update bleiben Kopplung, PIN und Einstellungen (`/etc/ida-connect/`) und der Port unverändert. Startet die neue Version
nicht, stellt das Install-Skript nach 15 Sekunden die alte wieder her. Nach einem Neustart des Geräts läuft der Dienst von selbst
wieder (`systemctl enable`), und systemd gibt nach Abstürzen nie auf.

**Über IDA Health (privates Repo):** Gekoppelte Geräte fragen zuerst Health nach der neuesten Version und laden Install-Skript und
Programm von dort (`/api/v1/agent/release`, `/install.sh`, `/download/<arch>`, angemeldet mit der Kopplung). Health holt alles mit
seinem GitHub-Token – das Repo darf privat sein, die Geräte brauchen keinen GitHub-Zugang. Ist Health nicht erreichbar oder älter,
geht es wie früher direkt zu GitHub. Auch der Install-Befehl aus Health lädt dann über Health (der Einmal-Code gilt als Anmeldung).

**Private Docker-Images:** Hat Health einen Token für Docker-Images (klassisch, nur `read:packages`), meldet es Geräte mit Docker beim Verbinden bei `ghcr.io` an
(`docker login` als root, Op `docker_login`; nur wenn sich der Zugang geändert hat). `docker compose pull` geht dann mit privaten
Images, Compose-Dateien bleiben gleich. Watchtower nutzt die Anmeldung, wenn `/root/.docker/config.json` in den Container
eingebunden ist (`- /root/.docker/config.json:/config.json:ro`).

## Cloudflare Mesh

Ist Health selbst im Mesh (IDA Health → Einstellungen → Cloudflare Mesh → „Health ins Mesh aufnehmen“), schickt es seine Mesh-Adresse
an alle Geräte. Ein Gerät, das selbst im Mesh ist, verbindet sich dann darüber; geht das nicht, über die öffentliche Adresse
(siehe PROTOCOL.md). `sudo ida-connect status` zeigt die Mesh-Adresse, die lokale Seite den aktuellen Weg.
Mit „nur Mesh“ (Einstellung in Health, Standard an) geht dann gar nichts mehr über das Internet, außer als Notweg nach 15 Minuten
ohne Mesh.

Mesh gleich bei der Installation: Der Befehl aus Health („Gerät hinzufügen“) enthält `--mesh-token` und `--mesh-server`. Das Skript
richtet damit vor dem ersten Start WARP ein (`ida-connect mesh`), und schon das Koppeln läuft übers Mesh. Von Hand:
`sudo ida-connect mesh <token> --server http://<mesh-ip>:<port>`.

Unterstützt: Linux mit systemd auf x86_64, aarch64 (Raspberry Pi OS 64-Bit) und armv7 (Raspberry Pi OS 32-Bit, ohne Mesh).

## Befehle auf dem Gerät

```sh
sudo ida-connect pin            # PIN der lokalen Seite
sudo ida-connect status         # gekoppelt? Server, Mesh-Adresse, Version, Auto-Update
sudo ida-connect pair <code>    # mit Code koppeln, danach: sudo systemctl restart ida-connect
sudo ida-connect server <url>   # andere Health-Adresse
systemctl status ida-connect    # läuft er?
sudo systemctl restart ida-connect
journalctl -u ida-connect -f    # Log
```

Konfiguration: `/etc/ida-connect/config.json` (nur root, enthält das Geräte-Secret).

## Sicherheit

* Die lokale Seite kann nur Status, Koppeln und Mesh – **keine** Shell und keine Dateien. Geschützt mit der PIN
  (5 Fehlversuche → 5 Minuten Pause), Sitzungs-Cookie `SameSite=Strict`.
* Koppeln über den Browser: Health bestätigt nur hinter Cloudflare Access, mit CSRF-Schutz; zurück kommt ein Einmal-Code
  (10 Minuten, einmal nutzbar). Danach meldet sich das Gerät mit einem eigenen Secret an (Health speichert nur den Hash).
* Alles Mächtige (Shell, Dateien, Docker, Updates) geht nur über Health hinter Cloudflare Zero Trust; jede Aktion steht
  im Protokoll des Geräts.
* Wird das Gerät in Health gelöscht, kann es sich nicht mehr anmelden.

## Entwickeln

```sh
cargo test && cargo clippy --release -- -D warnings
IDA_CONNECT_CONFIG=/tmp/ic.json IDA_CONNECT_SERVER=http://127.0.0.1:8096 IDA_CONNECT_LISTEN=127.0.0.1:1111 cargo run
```

Der Workflow `.github/workflows/release.yml` baut bei jedem Push auf `main` die Binaries (cargo-zigbuild, musl)
und legt ein GitHub-Release an (`releases/latest/download/ida-connect-<arch>`), das install.sh lädt.
