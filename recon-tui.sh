#!/usr/bin/env bash
#
# recon-tui.sh - terminal menu for recon.sh, built on whiptail (newt).
#
# No extra dependency: whiptail ships with Debian, Ubuntu and Kali. The TUI is
# only a front end; every action it performs is a plain recon.sh call, so the
# same run can always be reproduced from the command line it shows at the end.
#
# Screens:
#   - new scan       domain, options, concurrency and rate, then a live gauge
#   - results        pick a past run and open its summary or the raw files
#   - tool check     which recon tools are installed and usable
#   - quit
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECON="${RECON_SH:-$HERE/recon.sh}"
BASE_DIR="${RECON_TUI_BASE:-$PWD/recon}"
# The palm binary the TUI uses for reports and its own checks. recon.sh is told
# about it too, so the menu and the pipeline never disagree about which palm ran.
PALM_BIN="${PALM_BIN:-palm}"

PATH="$HOME/.local/bin:$HOME/go/bin:/usr/local/bin:$PATH"
export PATH

# ---------------------------------------------------------------- helpers ----
if ! command -v whiptail >/dev/null 2>&1; then
  cat >&2 <<'EOF'
error: whiptail is not installed, so the menu cannot be drawn.
  Debian/Ubuntu/Kali:  sudo apt-get install -y whiptail
  Or run the pipeline directly:  ./recon.sh -d example.com
EOF
  exit 1
fi

[ -x "$RECON" ] || RECON="$HERE/recon.sh"
if [ ! -f "$RECON" ]; then
  echo "error: recon.sh not found next to this script ($RECON)" >&2
  exit 1
fi

# whiptail draws on stderr and returns the answer on stderr, so every call swaps
# the two streams to capture the value.
WT_HEIGHT=20
WT_WIDTH=78
WT_LIST=12

msg()    { whiptail --title "$1" --msgbox "$2" $WT_HEIGHT $WT_WIDTH; }
err()    { whiptail --title "$1" --msgbox "$2" $WT_HEIGHT $WT_WIDTH; }
ask()    { whiptail --title "$1" --inputbox "$2" 12 $WT_WIDTH "${3:-}" 3>&1 1>&2 2>&3; }
confirm(){ whiptail --title "$1" --yesno "$2" 12 $WT_WIDTH; }
menu()   { whiptail --title "$1" --menu "$2" $WT_HEIGHT $WT_WIDTH $WT_LIST "${@:3}" 3>&1 1>&2 2>&3; }
checklist() { whiptail --title "$1" --checklist "$2" 22 $WT_WIDTH 10 "${@:3}" 3>&1 1>&2 2>&3; }

trim() { printf '%s' "$1" | tr -d '"' | tr -s ' '; }

# ---------------------------------------------------------------- new scan ----
do_scan() {
  local domain
  domain=$(ask "Yeni tarama" "Hedef domain (orn. example.com):") || return
  domain=$(printf '%s' "$domain" | tr -d ' ')
  [ -n "$domain" ] || return
  if ! printf '%s' "$domain" | grep -Eq '^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$'; then
    err "Hata" "Gecersiz domain: $domain"
    return
  fi

  local choices
  choices=$(checklist "Secenekler" "Kosacak asamalari sec (SPACE ile isaretle):" \
    "TAKEOVER" "Takeover kontrolu (onerilen)" ON \
    "PARAMS"   "Parametre/URL toplama (katana+gau)" ON \
    "HISTORY"  "gau/waybackurls gecmis URL'ler (yavas)" ON \
    "WAF"      "WAF tespiti (wafw00f + palm)" ON \
    "EXPORT"   "Rapor uret: html + json + xml" ON \
    "NUCLEI"   "nuclei sablon taramasi (cok yavas)" OFF \
    "AMASS"    "amass pasif enum (dakikalarca)" OFF) || return
  choices=$(trim "$choices")

  local conc rate timeout
  conc=$(ask "Paralellik" "Es zamanli worker sayisi:" "100") || return
  rate=$(ask "Hiz siniri" "Saniyedeki en fazla HTTP istegi (0 = sinirsiz):" "0") || return
  timeout=$(ask "Timeout" "Asama basina saniye:" "10") || return

  local args=("-d" "$domain" "-o" "$BASE_DIR/$domain" "-c" "${conc:-100}"
              "--timeout" "${timeout:-10}")
  [ "$PALM_BIN" != "palm" ] && args+=("--palm" "$PALM_BIN")
  [ "${rate:-0}" != "0" ] && args+=("--rate" "$rate")
  case " $choices " in *"TAKEOVER"*) ;; *) args+=("--no-takeover") ;; esac
  case " $choices " in *"PARAMS"*)   ;; *) args+=("--no-params")   ;; esac
  case " $choices " in *"HISTORY"*)  ;; *) args+=("--no-history")  ;; esac
  case " $choices " in *"WAF"*)      ;; *) args+=("--no-waf")      ;; esac
  case " $choices " in *"EXPORT"*)   args+=("--export" "html,json,xml") ;; *) args+=("--no-report") ;; esac
  case " $choices " in *"NUCLEI"*)   args+=("--with-nuclei")       ;; esac
  case " $choices " in *"AMASS"*)    args+=("--with-amass")        ;; esac

  local cmd="$RECON ${args[*]}"
  confirm "Onay" "Su komut kosacak:

  $cmd

Devam edilsin mi?" || return

  run_with_gauge "$domain" "$cmd"
}

# Progress is derived from recon.sh's own "==> N/6" stage lines, so the gauge
# reflects real work instead of a guess.
run_with_gauge() {
  local domain="$1" cmd="$2"
  local outdir="$BASE_DIR/$domain"
  local log="$outdir/run.log"
  mkdir -p "$outdir"

  local pid
  ( cd "$(dirname "$RECON")" && eval "$cmd" ) > "$log" 2>&1 &
  pid=$!

  (
    while kill -0 "$pid" 2>/dev/null; do
      # "==> 3/6" -> 3. Stripping every non-digit would glue "3" and "6" into
      # 36, so cut at the slash first.
      stage=$(grep -o '==> [0-9]/6' "$log" 2>/dev/null | tail -1 | sed 's|.*==> ||; s|/6||')
      case "$stage" in ''|*[!0-9]*) stage=0 ;; esac
      : "${stage:=0}"
      # Stage n of 6 maps to n*100/6, capped just below 100 while running.
      pct=$(( stage * 100 / 6 ))
      [ "$pct" -gt 97 ] && pct=97
      last=$(grep -E '^    ' "$log" 2>/dev/null | tail -1 | sed 's/\x1b\[[0-9;]*m//g' | cut -c1-64)
      printf 'XXX\n%d\nasama %s/6  %s\nXXX\n' "$pct" "$stage" "${last:-hazirlaniyor}"
      sleep 1
    done
    printf 'XXX\n100\nbitti\nXXX\n'
  ) | whiptail --title "Tarama: $domain" --gauge "Baslatiliyor..." 10 $WT_WIDTH 0

  wait "$pid" 2>/dev/null
  local rc=$?

  if [ $rc -eq 0 ]; then
    show_run "$outdir"
  else
    err "Tarama bitti (rc=$rc)" "Cikis kodu sifir degil. Log:

$log"
  fi
}

# ---------------------------------------------------------------- results -----
list_runs() {
  [ -d "$BASE_DIR" ] || return 1
  local d name
  for d in "$BASE_DIR"/*/; do
    [ -d "$d" ] || continue
    name=$(basename "$d")
    [ -f "$d/summary.txt" ] || continue
    printf '%s\n%s\n' "$name" "$(grep -c . "$d/live.txt" 2>/dev/null || echo 0) canli"
  done
}

show_run() {
  local outdir="$1"
  [ -f "$outdir/summary.txt" ] || { err "Sonuc" "Bu klasorde summary.txt yok:
$outdir"; return; }

  local choice
  choice=$(whiptail --title "Sonuclar: $(basename "$outdir")" --menu "Ne yapmak istersin?" \
    22 $WT_WIDTH 10 \
    "SUMMARY"  "Ozet raporu goster" \
    "LIVE"     "Canli URL listesi (live.txt)" \
    "SUBS"     "Tum subdomainler (subs.txt)" \
    "PARAMS"   "Parametre URL'leri (params.txt)" \
    "WAF"      "WAF listesi (waf.txt)" \
    "NUCLEI"   "Nuclei bulgulari (nuclei.txt)" \
    "REPORT"   "HTML/JSON/XML rapor uret (varsa ac)" \
    "LOG"      "Calisma logu" \
    "DIR"      "Klasoru ac (ls)" \
    "BACK"     "Geri don" 3>&1 1>&2 2>&3) || return

  local file=""
  case "$choice" in
    SUMMARY) file="$outdir/summary.txt" ;;
    LIVE)    file="$outdir/live.txt" ;;
    SUBS)    file="$outdir/subs.txt" ;;
    PARAMS)  file="$outdir/params.txt" ;;
    WAF)     file="$outdir/waf.txt" ;;
    NUCLEI)  file="$outdir/nuclei.txt" ;;
    REPORT)  make_report "$outdir"; return ;;
    LOG)     file="$outdir/run.log" ;;
    DIR)     whiptail --title "Klasor" --textbox <(ls -la "$outdir") 22 $WT_WIDTH || true; return ;;
    BACK)    return ;;
  esac

  # A menu entry that already handled its own action leaves file empty (or the
  # dialog was cancelled); nothing to display then.
  [ -n "$file" ] || return

  if [ -f "$file" ] && [ -s "$file" ]; then
    # Strip ANSI colours so the textbox does not show escape sequences.
    whiptail --title "$(basename "$file")" --textbox <(sed 's/\x1b\[[0-9;]*m//g' "$file") 24 $WT_WIDTH || true
  else
    err "Bos" "$(basename "$file") bos veya yok.
$file"
  fi
}

do_results() {
  local runs
  runs=$(list_runs)
  if [ -z "$runs" ]; then
    err "Sonuc yok" "Henuz tamamlanmis tarama yok.
Once 'Yeni tarama' sec."
    return
  fi

  local choice
  # shellcheck disable=SC2086
  choice=$(whiptail --title "Gecmis taramalar" --menu "Bir tarama sec:" \
    20 $WT_WIDTH 10 $runs 3>&1 1>&2 2>&3) || return

  show_run "$BASE_DIR/$choice"
}

# make_report renders report.html / results.json / results.xml from live.jsonl.
# palm -render does the work and needs no python; when the installed palm is too
# old the user is told what to install instead of failing silently.
make_report() {
  local outdir="$1"
  local jsonl="$outdir/live.jsonl"

  if [ ! -s "$jsonl" ]; then
    err "Rapor" "live.jsonl yok:
$jsonl"
    return
  fi

  local palm_bin made=""
  palm_bin="$PALM_BIN"
  command -v "$palm_bin" >/dev/null 2>&1 || palm_bin="palm"

  if [ -n "$palm_bin" ] && "$palm_bin" -h 2>/dev/null | grep -q -- '-render'; then
    "$palm_bin" -render "$jsonl" -format html -o "$outdir/report.html" 2>/dev/null && made="$made html"
    "$palm_bin" -render "$jsonl" -format json -o "$outdir/results.json" 2>/dev/null && made="$made json"
    "$palm_bin" -render "$jsonl" -format xml -o "$outdir/results.xml" 2>/dev/null && made="$made xml"
  fi

  if [ -z "$made" ]; then
    err "Rapor" "Rapor uretilemedi.
palm 0.7.1 veya daha yenisi (-render) gerekli.
Guncelle: sudo palm -update"
    return
  fi

  whiptail --title "Rapor" --msgbox "Uretildi:$made

Klasor: $outdir" 12 $WT_WIDTH || true
}

do_toolcheck() {
  local report=""
  local t state
  for t in subfinder assetfinder findomain amass katana gau waybackurls wafw00f nuclei "$PALM_BIN"; do
    if ! command -v "$t" >/dev/null 2>&1; then
      state="yok"
    else
      timeout 15 "$t" --version </dev/null >/dev/null 2>&1
      case $? in
        126|127) state="BOZUK" ;;
        *)       state="ok" ;;
      esac
    fi
    report+=$(printf '%-14s %s\n' "$t" "$state")
  done

  # Broken installs are common (a truncated download leaves a stub that only
  # prints "Not Found"), so point at the fix directly.
  report+=$'\n'"Bozuk bir arac varsa: sudo rm -f /usr/local/bin/<arac> && sudo apt-get install -y <arac>"
  whiptail --title "Arac kontrolu" --textbox <(printf '%s' "$report") 22 $WT_WIDTH || true
}

# ------------------------------------------------------------------ main -----
main_menu() {
  while true; do
    local choice
    choice=$(whiptail --title "palm recon" --menu "Ne yapmak istersin?" \
      18 $WT_WIDTH 6 \
      "NEW"     "Yeni tarama baslat" \
      "RESULTS" "Gecmis taramalara bak" \
      "TOOLS"   "Kurulu araclari kontrol et" \
      "QUIT"    "Cikis" 3>&1 1>&2 2>&3) || return 0

    case "$choice" in
      NEW)     do_scan ;;
      RESULTS) do_results ;;
      TOOLS)   do_toolcheck ;;
      QUIT)    return 0 ;;
    esac
  done
}

# Sourced by a test (RECON_TUI_NO_MAIN=1) exposes the functions without opening
# the menu.
[ "${RECON_TUI_NO_MAIN:-0}" = "1" ] || main_menu
