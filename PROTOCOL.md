# Protokoll ida-connect ↔ IDA Health

Eine einzige WebSocket-Verbindung, die **das Gerät aufbaut** (ausgehend, kein offener Port nötig):
`wss://<health>/api/v1/agent/ws`. Alle Nachrichten sind JSON-Textframes mit dem Feld `t` (Typ).
Dieselbe Datei liegt in IDA-PA unter `docs/HEALTH-PROTOKOLL.md` – Änderungen immer in beiden.

## Anmeldung

Header `Authorization` beim Verbindungsaufbau:

* `Bearer <device_id>:<secret>` – normales Gerät. Health speichert nur SHA-256 des Secrets.
* `Pair <code>` – Erstverbindung mit einem Einmal-Code (gültig 10 Minuten, einmal nutzbar).
  Health antwortet als erste Nachricht `{"t":"paired","id":"…","secret":"…","name":"…"}`; das Gerät speichert beides
  und läuft danach in derselben Verbindung normal weiter.

Falsche Anmeldung: Health schließt mit Code 4401 (Gerät gelöscht/Secret falsch → nicht ständig neu versuchen, nur alle 5 Minuten).

## Gerät → Health

| t | Inhalt |
|---|---|
| `hello` | `v` (Protokoll 1), `agent` (Version), `info` (s. u.) – erste Nachricht nach dem Aufbau |
| `info` | `info` – wenn sich etwas ändert (z. B. Mesh), sonst alle 10 Minuten |
| `m` | Messwerte (s. u.), alle `interval` Sekunden |
| `res` | Antwort auf `req`: `id`, `ok`, `data` oder `error` |
| `pty_out` | `sid`, `d` (Base64) |
| `pty_exit` | `sid`, `code` |

`info`: `hostname, os, kernel, arch, cpu_model, cores, mem_total, mode (systemd), mesh {ip, status}, boot (Unix-Zeit),
route ("mesh" | "public" – über welchen Weg das Gerät gerade verbunden ist), auto_update (bool), update {current, latest, available}`

`m` (kompakt, Bytes/Bytes pro Sekunde, °C, U/min):
```json
{"t":"m","ts":1763700000,"cpu":12.5,"cores":[10.1,14.9],"mem":[used,total],"swap":[used,total],
 "load":[0.3,0.2,0.1],"up":12345,"procs":180,
 "temps":[["cpu",48.2]],"fans":[["fan1",1200]],
 "disks":[["/",used,total]],"net":[["eth0",rx_bps,tx_bps]],"io":[["mmcblk0",read_bps,write_bps]]}
```

## Health → Gerät

| t | Inhalt |
|---|---|
| `config` | `interval` (Sekunden, 1–300) – z. B. 10 normal, 2 solange jemand live zuschaut; `mesh_server` (Adresse von Health im Cloudflare Mesh, z. B. `http://100.96.0.5:8000`, leer = nicht im Mesh; fehlt das Feld, bleibt der alte Wert); `mesh_only` (true = nur noch über das Mesh, siehe unten) |
| `req` | `id`, `op`, weitere Felder je nach `op` (s. u.) |
| `pty_open` | `sid`, `cols`, `rows` – neue Shell (bash -l, sonst sh) als root auf dem Gerät |
| `pty_in` | `sid`, `d` (Base64) |
| `pty_resize` | `sid`, `cols`, `rows` |
| `pty_close` | `sid` |
| `ping` | Gerät antwortet `{"t":"pong"}` |

### Operationen (`req.op`)

| op | Felder | `data` |
|---|---|---|
| `exec` | `cmd`, `timeout` (s, max 3600), `user?` | `code, stdout, stderr, timeout (bool)` |
| `fs_list` | `path` | `path, entries: [[name, typ d/f/l, size, mtime, mode]]` |
| `fs_read` | `path`, `offset?`, `len?` (max 4 MB) | `size, d (Base64), eof` |
| `fs_write` | `path`, `d` (Base64), `append?`, `mkdirs?` | `size` |
| `fs_delete` | `path`, `recursive?` | – |
| `fs_mkdir` | `path` | – |
| `fs_rename` | `from`, `to` | – |
| `mesh_setup` | `token` | `output` – installiert cloudflare-warp und meldet das Gerät als Mesh-Knoten an |
| `mesh_status` | – | `ip, status` |
| `update` | – | startet das Update von ida-connect (Install-Skript in eigener systemd-Unit; Kopplung bleibt, bei Fehlstart zurück zur alten Version) |
| `update_check` | – | `current, latest, available, checked, error` – fragt GitHub (`…/releases/latest`) |
| `set_auto_update` | `on` (bool) | `auto_update` – neue Versionen selbst installieren (alle 6 Stunden nachsehen) |
| `info` | – | wie `info` |
| `heal_list` | – | `rules: [{id, name, enabled, check, target, action, cmd, interval, fails, cooldown, max_per_hour, state}]`, `events` (letzte 50) |
| `heal_set` | `rule` (ohne `id` = neu, mit `id` = ändern) | wie `heal_list` |
| `heal_delete` | `rule_id` | wie `heal_list` |
| `heal_check` | `rule_id` | `{ok, error?}` – Prüfung jetzt ausführen, ohne Aktion |
| `health` | – | Gesundheitsbericht, s. u. |
| `fan_list` | – | `fans: [{id, name, rpm, percent, config}]` (nur Lüfter mit beschreibbarem PWM, hwmon `pwmN`), `sensors: [Name]` (mögliche Fühler für die Kurve) |
| `fan_set` | `fan` (Lüfter-id), `mode` (`auto` \| `fixed` \| `curve`), `percent` (0–100, bei `fixed`), `curve` (`[[°C, %], …]`, 2–20 Punkte, bei `curve`), `sensor?` (leer = heißester Fühler) | wie `fan_list` |

`health`: `{status: ok|warn|fail, problems: [Text], smart, cards, filesystems, power}`
* `smart`: `{available, hint?, devices: [{name, type, model, serial, size, rotational, passed, temp, power_on_hours, wear_used?, ata?{reallocated, pending, uncorrectable, crc_errors, life_left}, nvme?{percentage_used, available_spare, media_errors, …}, status, problems, standby?}]}` –
  braucht `smartctl` (Paket smartmontools; fehlt es: `available:false` + `hint`). Schlafende Platten werden nicht geweckt (`standby:true`).
* `cards`: SD/eMMC (`/sys/block/mmcblk*`): `{name, kind (SD|eMMC), model, size, written_since_boot, wear_known, wear_used (%), pre_eol, status}`.
  Verschleiß melden nur eMMC (`life_time`); normale SD-Karten nicht (`wear_known:false`) – dann zählen Fehler und Schreibmenge.
* `filesystems`: `{mounts: [{device, mount, type, read_only, errors (ext4-Fehlerzähler), status}], kernel_log: [Zeilen mit I/O-, ext4-, mmc-Fehlern]}`.
  `/` nur lesbar = `fail` (typisch nach Dateisystemfehlern).
* `power` (nur Raspberry Pi, sonst `null`): `vcgencmd get_throttled` entschlüsselt: `undervoltage`, `freq_capped`, `throttled`, `soft_temp_limit` und je `…_seen` (seit dem Start), `raw`.
  Zusätzlich steht in jeder Messung `m.undervolt` (bool|null, Pi: Unterspannung gerade jetzt).

Selbstheilung (`heal_*`): Regel „wenn `check` auf `target` fehlschlägt, dann `action`“.
* `check`: `container` (läuft, bei Healthcheck auch nicht `unhealthy`; Name), `service` (systemd-Dienst), `http` (URL, per curl, Erfolg = 2xx/3xx), `tcp` (`host:port`), `command` (Shell-Befehl, Exit-Code 0 = gesund).
* `action`: `restart` (nur bei `container`/`service`: `docker restart` bzw. `systemctl restart`) oder `command` (Shell-Befehl `cmd`, als root).
* Schutz: erst nach `fails` Fehlschlägen in Folge (Standard 3, Prüfung alle `interval` s, Standard 30), zwischen zwei Aktionen mindestens `cooldown` s (300),
  höchstens `max_per_hour` Aktionen pro Stunde (3) – danach `state.status = gave_up`, bis die Prüfung wieder klappt. Regeln liegen in der Config, die Prüfung läuft auch ohne Verbindung zu Health.
* `state.status`: `unknown`, `ok`, `failing`, `healing` (Aktion lief, wartet auf Erholung), `gave_up`, `disabled`.
* Ereignisse kommen zusätzlich als `{"t":"heal","events":[{seq, ts, rule, name, kind (action|recovered|gave_up), ok, msg}]}` (Gerät → Health, mit den Messwerten gesendet).
* Ein bewusst gestoppter Container wird bei einer aktiven Regel wieder gestartet – dafür die Regel deaktivieren (`enabled:false`).

(`id` ist in Anfragen die Anfrage-Nummer – deshalb heißen die Felder `fan` und `rule_id`.)

Lüfter: `config` = `{mode, percent, curve, sensor}`. Der Agent speichert die Einstellung in der Config und regelt Kurven alle 3 Sekunden
(linear zwischen den Punkten, unter/über den Endpunkten deren Wert; ist keine Temperatur lesbar → 100 %). `auto` gibt den Lüfter an das Gerät
zurück (`pwmN_enable` wie vorher), das passiert auch, wenn der Dienst beendet wird.

Pfade sind immer absolute Pfade auf dem Gerät.


## Weg der Verbindung (Mesh oder öffentlich)

Hat Health eine Mesh-Adresse geschickt (`config.mesh_server`) und ist WARP auf dem Gerät verbunden, verbindet sich der Agent zuerst
über das Mesh (6 s Zeitlimit). Klappt das nicht, sofort über die öffentliche Adresse (`server`) und 5 Minuten lang nicht wieder über
das Mesh. Ist das Gerät über die öffentliche Adresse verbunden, prüft es alle 5 Minuten per TCP, ob Health im Mesh erreichbar ist,
und wechselt dann. Über die Mesh-IP nimmt Health nur `/api/v1/agent/*` an.

**Nur Mesh** (`config.mesh_only`, Standard in Health an): Ist WARP auf dem Gerät eingerichtet und kennt es die Mesh-Adresse, nimmt
der Agent nur noch das Mesh. Ist WARP getrennt, startet er `warp-svc` neu und ruft `warp-cli connect` auf. Die öffentliche Adresse
gibt es dann nur noch
* zum Koppeln, solange WARP hier noch nicht verbunden ist,
* auf Geräten ohne WARP (32-Bit, noch nicht eingerichtet),
* als **Notweg**, wenn das Mesh 15 Minuten lang nicht geht. Dann prüft der Agent jede Minute, ob das Mesh wieder geht, und wechselt zurück.
