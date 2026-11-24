#!/bin/sh
# ida-connect als Systemdienst (systemd) installieren, aktualisieren oder entfernen – ein Befehl, alles von GitHub:
#
#   curl -fsSL https://raw.githubusercontent.com/L8teNever/Ida-connect/main/install.sh | sudo sh
#   … | sudo sh -s -- --code abc123-def456-789abc          # direkt koppeln (Code aus IDA Health → „Gerät hinzufügen“)
#   … --mesh-token <token> --mesh-server http://<mesh-ip>:<port>
#                                                          # vorher Cloudflare Mesh einrichten (WARP) – dann läuft schon das
#                                                          # Koppeln übers Mesh (Health hängt das an den Befehl an)
#   … | sudo sh -s -- --update                             # neue Version holen – oder einfach: sudo ida-connect update
#                                                          # (Auto-Update macht das alle 6 Stunden selbst; Health hat einen Knopf)
#   … | sudo sh -s -- --uninstall [--purge]                # entfernen (--purge: auch Kopplung/Config)
#
# Weitere Optionen: --server https://health.example.com (Adresse von IDA Health; steht im Befehl aus Health), --port 1111
#
# Das Programm kommt über IDA Health, wenn möglich (beim Koppeln mit --code, bei Updates des Agenten mit --health): Health holt es
# mit seinem GitHub-Zugang – das Repo darf also privat sein. Geht das nicht, wird wie früher direkt von GitHub geladen.
set -eu

REPO="L8teNever/Ida-connect"
DL="https://github.com/${REPO}/releases/latest/download"
BIN=/usr/local/bin/ida-connect
CONF_DIR=/etc/ida-connect
UNIT=/etc/systemd/system/ida-connect.service
SERVER=""
CODE=""
PORT=""
MESH_TOKEN=""
MESH_SERVER=""
HEALTH=""
HDR=""
ACTION=install
PURGE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --server) SERVER="$2"; shift 2 ;;
    --code) CODE="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --mesh-token) MESH_TOKEN="$2"; shift 2 ;;
    --mesh-server) MESH_SERVER="$2"; shift 2 ;;
    --health) HEALTH="$2"; shift 2 ;;
    --update) ACTION=update; shift ;;
    --uninstall) ACTION=uninstall; shift ;;
    --purge) PURGE=1; shift ;;
    -h|--help) sed -n 2,16p "$0" 2>/dev/null || true; exit 0 ;;
    *) echo "Unbekannte Option: $1" >&2; exit 2 ;;
  esac
done

# Ausgaben dürfen nie abbrechen: läuft das Update im Terminal von IDA Health, verschwindet das Terminal beim Neustart des Dienstes
say() { printf '\033[1;36m›\033[0m %s\n' "$*" 2>/dev/null || true; }
die() { printf '\033[1;31m✗\033[0m %s\n' "$*" >&2; exit 1; }

# Port: angegeben, sonst der bisherige aus dem Dienst (Update), sonst 1111
if [ -z "$PORT" ]; then
  PORT=$(sed -n 's/^Environment=IDA_CONNECT_LISTEN=.*:\([0-9]*\)$/\1/p' "$UNIT" 2>/dev/null | head -1)
  [ -n "$PORT" ] || PORT=1111
fi

[ "$(id -u)" = 0 ] || die "Bitte als root ausführen (sudo sh)."
command -v curl >/dev/null 2>&1 || die "curl fehlt (z. B. apt-get install -y curl)."

arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo x86_64 ;;
    aarch64|arm64) echo aarch64 ;;
    armv7l|armv7*|armhf) echo armv7 ;;
    *) die "Prozessor $(uname -m) wird nicht unterstützt (x86_64, aarch64, armv7)." ;;
  esac
}

ip_hint() {
  ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || hostname -I 2>/dev/null | awk '{print $1}'
}

prepare_config() {
  # Server und Code an den Agenten geben (Datei wird vom Dienst beim Start gelesen)
  mkdir -p "$CONF_DIR"
  chmod 700 "$CONF_DIR"
  if [ -n "$CODE" ]; then
    printf '%s' "$CODE" > "$CONF_DIR/pair-code"
    chmod 600 "$CONF_DIR/pair-code"
  fi
}

set_server_native() {
  if [ -n "$SERVER" ]; then "$BIN" server "$SERVER" >/dev/null; fi
  "$BIN" pin >/dev/null  # legt die Config mit PIN an
}

finish() {
  sleep 3
  IP=$(ip_hint)
  PIN=$("$BIN" pin)
  echo
  if systemctl is-active --quiet ida-connect; then say "ida-connect läuft als Systemdienst."; else
    printf '\033[1;31m✗\033[0m Dienst läuft nicht – siehe: journalctl -u ida-connect -n 50\n' >&2; fi
  echo "   Lokale Seite:  http://${IP:-<gerät>}:${PORT}"
  echo "   PIN:           ${PIN}"
  if [ -n "$CODE" ]; then
    echo "   Koppeln:       läuft mit dem Code – das Gerät erscheint gleich in IDA Health."
    if [ "$MESH_OK" = 1 ]; then echo "   Mesh:          eingerichtet – Health spricht nur noch über das Mesh mit dem Gerät."; fi
  else
    echo "   Koppeln:       Seite öffnen, mit der PIN anmelden, „Mit IDA verbinden“."
  fi
  echo
}

setup_mesh() {
  # Mesh vor dem ersten Start: WARP installieren und mit dem Knoten verbinden. Geht das schief, koppelt das Gerät über die
  # öffentliche Adresse, und Health versucht das Mesh danach selbst noch einmal.
  [ -n "$MESH_TOKEN$MESH_SERVER" ] || return 0
  if [ -n "$MESH_TOKEN" ]; then say "Richte Cloudflare Mesh ein (WARP) – das dauert ein bis drei Minuten …"; fi
  if [ -n "$MESH_SERVER" ]; then set -- --server "$MESH_SERVER"; else set --; fi
  if IDA_CONNECT_MESH_TOKEN="$MESH_TOKEN" "$BIN" mesh "$@"; then
    MESH_OK=1
  else
    printf '\033[1;33m!\033[0m Mesh-Einrichtung hat nicht geklappt – koppeln läuft über das Internet, Health versucht es danach noch einmal.\n' >&2 2>/dev/null || true
  fi
}
MESH_OK=0

# SMART-Werte von SSD/HDD (Gesundheitscheck in IDA Health) brauchen smartctl. Wird bei Installation UND Update nachgeholt, damit jedes
# Gerät es hat. Bester Versuch: klappt es nicht (kein Paketmanager, kein Netz, apt belegt), läuft ida-connect trotzdem normal.
ensure_smartctl() {
  command -v smartctl >/dev/null 2>&1 && return 0
  if command -v apt-get >/dev/null 2>&1; then
    say "Installiere smartmontools (SMART-Gesundheit der Laufwerke) …"
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq -o DPkg::Lock::Timeout=120 smartmontools >/dev/null 2>&1 \
      || { apt-get update -qq -o DPkg::Lock::Timeout=120 >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq -o DPkg::Lock::Timeout=120 smartmontools >/dev/null 2>&1; }
  elif command -v dnf >/dev/null 2>&1; then say "Installiere smartmontools …"; dnf install -y -q smartmontools >/dev/null 2>&1
  elif command -v yum >/dev/null 2>&1; then say "Installiere smartmontools …"; yum install -y -q smartmontools >/dev/null 2>&1
  elif command -v zypper >/dev/null 2>&1; then say "Installiere smartmontools …"; zypper -q --non-interactive install smartmontools >/dev/null 2>&1
  elif command -v apk >/dev/null 2>&1; then say "Installiere smartmontools …"; apk add -q smartmontools >/dev/null 2>&1
  elif command -v pacman >/dev/null 2>&1; then say "Installiere smartmontools …"; pacman -S --noconfirm --needed smartmontools >/dev/null 2>&1
  else
    return 0
  fi
  command -v smartctl >/dev/null 2>&1 || printf '\033[1;33m!\033[0m smartmontools ließ sich nicht installieren – SMART-Werte fehlen in Health (später: apt install smartmontools).\n' >&2 2>/dev/null || true
}

# Anmeldung bei Health für den Download: beim Koppeln der Einmal-Code, beim Update die Datei, die der Agent schreibt.
# Als Datei an curl (-H @datei), damit nichts davon in der Prozessliste steht.
health_auth() {
  if [ -n "$HEALTH" ] && [ -r "$CONF_DIR/health-auth" ]; then
    HDR="$CONF_DIR/health-auth"
  elif [ -n "$CODE" ] && [ -n "$SERVER" ]; then
    HEALTH="$SERVER"
    HDR=$(mktemp)
    chmod 600 "$HDR"
    printf 'Authorization: Pair %s\n' "$CODE" > "$HDR"
    TMP_HDR="$HDR"
  fi
}
TMP_HDR=""

download() {
  # $1 = Ziel. Zuerst über Health, sonst GitHub.
  health_auth
  if [ -n "$HEALTH" ] && [ -n "$HDR" ]; then
    say "Lade ida-connect ($A) über IDA Health …"
    if curl -fsSL --retry 2 --connect-timeout 10 -H @"$HDR" -o "$1" "${HEALTH%/}/api/v1/agent/download/$A"; then
      [ -z "$TMP_HDR" ] || rm -f "$TMP_HDR"
      return 0
    fi
    [ -z "$TMP_HDR" ] || rm -f "$TMP_HDR"
    printf '\033[1;33m!\033[0m Über Health ging es nicht – versuche GitHub.\n' >&2 2>/dev/null || true
  fi
  say "Lade ida-connect ($A) von GitHub …"
  curl -fsSL --retry 3 -o "$1" "$DL/ida-connect-$A"
}

install_native() {
  command -v systemctl >/dev/null 2>&1 || die "Kein systemd gefunden – ida-connect läuft als systemd-Dienst."
  A=$(arch)
  TMP=$(mktemp)
  download "$TMP" || { rm -f "$TMP"; die "Download fehlgeschlagen (Health und $DL/ida-connect-$A). Ist das Repo privat, braucht Health einen GitHub-Token (Einstellungen → GitHub)."; }
  chmod 755 "$TMP"
  "$TMP" --version >/dev/null 2>&1 || { rm -f "$TMP"; die "Die geladene Datei läuft hier nicht."; }
  NEW=$("$TMP" --version | awk '{print $2}')
  OLD=""
  if [ -x "$BIN" ]; then
    OLD=$("$BIN" --version 2>/dev/null | awk '{print $2}')
    cp -f "$BIN" "$BIN.prev"   # für den Fall, dass die neue Version nicht startet
  fi
  mv -f "$TMP" "$BIN"
  prepare_config
  set_server_native
  setup_mesh
  cat > "$UNIT" <<EOF
[Unit]
Description=ida-connect (Agent für IDA Health)
After=network-online.target
Wants=network-online.target
# nie aufgeben: auch nach vielen Abstürzen weiter neu starten
StartLimitIntervalSec=0

[Service]
ExecStart=$BIN
Environment=IDA_CONNECT_LISTEN=0.0.0.0:$PORT
Restart=always
RestartSec=5
# klein halten: der Agent braucht nur ein paar MB
MemoryMax=64M
Nice=5

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable ida-connect >/dev/null 2>&1
  systemctl restart ida-connect
  # Startet die neue Version nicht, kommt die alte zurück (wichtig bei Auto-Update auf Geräten, an die man schlecht rankommt).
  # Dreimal über ~20 s prüfen, damit ein Absturz-Kreislauf nicht zufällig im kurzen „active“-Moment durchrutscht.
  if [ -n "$OLD" ] && [ -x "$BIN.prev" ]; then
    OK=1
    for _ in 1 2 3; do
      sleep 7
      systemctl is-active --quiet ida-connect || OK=0
    done
    if [ "$OK" = 0 ]; then
      mv -f "$BIN.prev" "$BIN"           # erst zurückrollen, dann reden
      systemctl restart ida-connect || true
      printf '\033[1;31m✗\033[0m Version %s startet nicht – %s wiederhergestellt.\n' "$NEW" "$OLD" >&2 2>/dev/null || true
      exit 1
    fi
  fi
  ensure_smartctl || true   # erst nach der Rollback-Prüfung: ein langsames apt darf sie nicht stören
  if [ -n "$OLD" ] && [ "$OLD" != "$NEW" ]; then
    say "Aktualisiert: $OLD → $NEW (Kopplung und Einstellungen in $CONF_DIR unverändert)."
  else
    say "Installiert: ida-connect $NEW als Systemdienst (startet auch nach jedem Neustart des Geräts)."
  fi
}

case "$ACTION" in
  install)
    install_native
    finish ;;
  update)
    say "Aktualisiere ida-connect …"
    install_native
    say "Fertig." ;;
  uninstall)
    systemctl disable --now ida-connect >/dev/null 2>&1 || true
    rm -f "$UNIT" "$BIN" "$BIN.prev"
    systemctl daemon-reload || true
    if [ "$PURGE" = 1 ]; then rm -rf "$CONF_DIR"; fi
    say "ida-connect entfernt.$( [ "$PURGE" = 1 ] || echo " Kopplung bleibt in $CONF_DIR (--purge löscht sie).")" ;;
esac
