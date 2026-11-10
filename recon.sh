#!/usr/bin/env bash
#
# recon.sh - one-pass bug bounty recon built around palm.
#
# Stages (each writes into its own file under the output directory):
#   1. enum    passive subdomain discovery with subfinder/assetfinder/findomain
#              (amass is opt-in with --with-amass because it is slow)
#   2. dns     resolve + wildcard filtering with palm
#   3. live    HTTP probe, takeover and TLS summary with palm
#   4. params  crawl the live hosts and collect URLs that carry parameters
#   5. waf     identify a WAF in front of each live host (wafw00f, with palm -waf as fallback)
#   6. nuclei  template scan, opt-in because it is the slowest stage
#
# Every external tool is optional: a missing one skips its stage with a notice
# instead of failing the run. Stages are resumable, so a second run with the same
# output directory only redoes the stages whose output is missing.
#
# Usage:
#   ./recon.sh -d example.com
#   ./recon.sh -d example.com -o recon/example -c 100 --with-nuclei
#   ./recon.sh -d example.com --rate 5 --no-params
#
set -uo pipefail

# Tools installed with `go install` or a user-level installer land in
# ~/.local/bin or ~/go/bin. A login shell usually adds them, but cron and plain
# `bash script.sh` do not, so add the common locations explicitly.
PATH="$HOME/.local/bin:$HOME/go/bin:$HOME/.cargo/bin:/usr/local/bin:$PATH"
export PATH

DOMAIN=""
OUTDIR=""
INPUT_FILE=""
CONCURRENCY=100
TIMEOUT=10
RATE=0
RUN_PARAMS=1
RUN_HISTORY=1
RUN_WAF=1
RUN_NUCLEI=0
RUN_TAKEOVER=1
RUN_AMASS=0
RUN_REPORT=1
# Which formats to render from live.jsonl at the end of a run.
EXPORT_FORMATS="html"
NUCLEI_TEMPLATES="${NUCLEI_TEMPLATES:-}"
NUCLEI_SEVERITY="${NUCLEI_SEVERITY:-critical,high,medium}"
FORCE=0
PALM_BIN="${PALM_BIN:-palm}"

usage() {
  cat <<'EOF'
recon.sh - subdomain recon pipeline built around palm

Usage:
  ./recon.sh -d <domain> [options]

Required:
  -d, --domain <domain>   target domain, for example example.com

Options:
  -i, --input <file>      reuse an existing subdomain list and skip enumeration
  -o, --out <dir>         output directory (default: recon/<domain>)
  -c, --concurrency <n>   parallel hosts for palm and crawlers (default 100)
      --timeout <sec>     per-phase timeout handed to palm (default 10)
      --rate <n>          max HTTP requests per second for palm (0 = unlimited)
      --palm <path>       palm binary to use (default: palm from PATH)
      --no-params         skip URL/parameter collection
      --no-history        skip gau/waybackurls (slow, many network calls)
      --no-waf            skip the WAF fingerprint stage
      --no-takeover       skip takeover checks in the live stage
      --with-amass        also run amass (slow: many sources, often minutes)
      --with-nuclei       add the nuclei template scan (slow)
      --no-report         skip the HTML report at the end
      --export <list>     formats to render from the results: json, xml, html
                          (comma or space separated; default: html)
                          example: --export json,xml,html
      --nuclei-severity <list>
                          nuclei severities (default: critical,high,medium)
      --nuclei-templates <dir>
                          template directory to use (default: auto-detect)
      --force             rerun stages even when their output already exists
  -h, --help              show this help

Examples:
  ./recon.sh -d example.com
  ./recon.sh -d example.com --rate 5 -c 50
  ./recon.sh -d example.com -i subs.txt --no-params
  ./recon.sh -d example.com -o /tmp/recon --with-nuclei --force

Output layout:
  <out>/subs.txt        all discovered subdomains
  <out>/resolved.txt    subdomains that resolve (wildcards filtered)
  <out>/live.txt        live URLs (one per line)
  <out>/live.jsonl      palm JSON: status, title, server, tls, takeover
  <out>/params.txt      parameterised URLs found by crawling
  <out>/params.uniq     deduplicated parameter names
  <out>/waf.txt         WAF per host
  <out>/nuclei.txt      nuclei findings (only with --with-nuclei)
  <out>/summary.txt     human readable report
  <out>/report.html    shareable HTML report (see --export)
  <out>/results.json   full JSON array when --export json is given
  <out>/results.xml    XML report when --export xml is given

Only scan assets you own or are authorised to test.
EOF
}

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
ok()   { printf '    \033[32mok\033[0m %s\n' "$*"; }
warn() { printf '    \033[33m!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

# palm_supports reports whether the installed palm knows a flag. recon.sh keeps
# working with an older palm instead of failing a whole stage on an unknown flag.
palm_supports() {
  "$PALM_BIN" -h 2>/dev/null | grep -q -- "$1"
}

# A tool can be installed and still be unusable: a truncated download (a 9-byte
# "Not Found" stub is a real case) exits 126/127 instead of running. A slow tool
# is not broken, so a timeout counts as usable.
tool_usable() {
  local bin="$1"; shift
  have "$bin" || return 1
  timeout 20 "$bin" "$@" </dev/null >/dev/null 2>&1
  local rc=$?
  case "$rc" in
    126|127) return 1 ;;   # not executable / not found: broken install
    *)       return 0 ;;   # ok, or 124 (timed out = slow but present)
  esac
}

while [ $# -gt 0 ]; do
  case "$1" in
    -d|--domain)      DOMAIN="${2:-}"; shift 2 ;;
    -i|--input)       INPUT_FILE="${2:-}"; shift 2 ;;
    -o|--out)         OUTDIR="${2:-}"; shift 2 ;;
    -c|--concurrency) CONCURRENCY="${2:-}"; shift 2 ;;
    --timeout)        TIMEOUT="${2:-}"; shift 2 ;;
    --rate)           RATE="${2:-}"; shift 2 ;;
    --palm)           PALM_BIN="${2:-}"; shift 2 ;;
    --no-params)      RUN_PARAMS=0; shift ;;
    --no-history)     RUN_HISTORY=0; shift ;;
    --no-waf)         RUN_WAF=0; shift ;;
    --no-takeover)    RUN_TAKEOVER=0; shift ;;
    --with-amass)     RUN_AMASS=1; shift ;;
    --with-nuclei)    RUN_NUCLEI=1; shift ;;
    --no-report)      RUN_REPORT=0; EXPORT_FORMATS=""; shift ;;
    --export)         EXPORT_FORMATS="$(printf '%s' "${2:-}" | tr ',' ' ')"; shift 2 ;;
    --nuclei-severity) NUCLEI_SEVERITY="${2:-}"; shift 2 ;;
    --nuclei-templates) NUCLEI_TEMPLATES="${2:-}"; shift 2 ;;
    --force)          FORCE=1; shift ;;
    -h|--help)        usage; exit 0 ;;
    *)                die "unknown argument: $1 (try --help)" ;;
  esac
done

[ -n "$DOMAIN" ] || { usage; exit 1; }
case "$DOMAIN" in
  *[!a-zA-Z0-9.-]*) die "invalid domain: $DOMAIN" ;;
esac
[ -n "$OUTDIR" ] || OUTDIR="recon/$DOMAIN"
mkdir -p "$OUTDIR" || die "cannot create $OUTDIR"

# Work with an absolute path from here on. Tools that honour XDG_CONFIG_HOME
# (subfinder among them) create a stray ./<tool> directory in the current
# directory when the value is relative, because the XDG spec requires absolute
# paths and they do not check.
OUTDIR="$(cd "$OUTDIR" && pwd)" || die "cannot resolve $OUTDIR"

# Every stage writes into OUTDIR, so a directory owned by another user (a run
# under sudo is the usual cause) fails much later with a confusing message.
probe="$OUTDIR/.write-test"
# stderr is redirected before the file is opened, so a failure stays silent and
# the friendly message below is the only output.
if ! : 2>/dev/null > "$probe"; then
  die "$OUTDIR is not writable.
  If it was created by root, fix the owner:  sudo chown -R \$USER $OUTDIR
  Or write somewhere else:                   -o ~/recon/$DOMAIN"
fi
rm -f "$probe"

have "$PALM_BIN" || die "$PALM_BIN not found in PATH; install it or pass --palm /path/to/palm"

SUBS="$OUTDIR/subs.txt"
RESOLVED="$OUTDIR/resolved.txt"
LIVE="$OUTDIR/live.txt"
LIVE_JSON="$OUTDIR/live.jsonl"
PARAMS="$OUTDIR/params.txt"
PARAMS_UNIQ="$OUTDIR/params.uniq"
WAF_OUT="$OUTDIR/waf.txt"
NUCLEI_OUT="$OUTDIR/nuclei.txt"
REPORT_OUT="$OUTDIR/report.html"
SUMMARY="$OUTDIR/summary.txt"
LOG="$OUTDIR/run.log"

: > "$LOG"
# Everything printed also lands in the log for later review.
exec > >(tee -a "$LOG") 2>&1

stage_done() { [ "$FORCE" -eq 0 ] && [ -s "$1" ]; }

start=$(date +%s)
log "target: $DOMAIN"
log "output: $OUTDIR"
log "palm:   $($PALM_BIN -version 2>/dev/null || echo "$PALM_BIN")"

# Some recon tools write a config file under XDG_CONFIG_HOME and fail when the
# default location is not writable (a common state on a shared machine). Keep
# their config inside the output directory so the pipeline never touches $HOME.
export XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$OUTDIR/.config}"
mkdir -p "$XDG_CONFIG_HOME" 2>/dev/null || true

# Every external tool runs inside this directory, so anything it drops on disk
# (caches, half-written config, a stray ./subfinder) lands in the output folder
# instead of wherever the user started the script.
SCRATCH="$OUTDIR/.work"
mkdir -p "$SCRATCH" || die "cannot create $SCRATCH"

# A source tool that asks for a password or waits on stdin would stall the whole
# run, so every external call gets a timeout and a closed stdin.
SRC_TIMEOUT=180

# ---------------------------------------------------------------- 1. enum ----
if [ -n "$INPUT_FILE" ]; then
  [ -r "$INPUT_FILE" ] || die "cannot read input file: $INPUT_FILE"
  log "1/6 enumeration skipped, using $INPUT_FILE"
  if stage_done "$SUBS" && [ "$FORCE" -eq 0 ]; then
    ok "enum: reusing $SUBS ($(wc -l < "$SUBS" | tr -d ' ') hosts)"
  else
    # Keep a normalised, deduplicated copy so later stages read one clean list.
    tr '[:upper:]' '[:lower:]' < "$INPUT_FILE" | sort -u > "$SUBS"
    ok "enum: $(wc -l < "$SUBS" | tr -d ' ') hosts from input"
  fi
elif stage_done "$SUBS"; then
  ok "enum: reusing $SUBS ($(wc -l < "$SUBS" | tr -d ' ') hosts)"
else
  log "1/6 passive subdomain enumeration"
  : > "$SUBS"
  enum_dir="$OUTDIR/.enum"
  mkdir -p "$enum_dir"
  rm -f "$enum_dir"/*.txt

  # Enumerators run in parallel: they are independent, and one slow provider
  # should not delay the others.
  pids=()
  names=()
  launch_enum() {
    local name="$1"; shift
    names+=("$name")
    ( cd "$SCRATCH" && timeout "$SRC_TIMEOUT" "$@" </dev/null 2>/dev/null \
        | tr '[:upper:]' '[:lower:]' > "$enum_dir/$name.txt" ) &
    pids+=($!)
  }

  if tool_usable subfinder -version; then
    launch_enum subfinder subfinder -d "$DOMAIN" -silent -all
  else
    warn "subfinder unusable or missing"
  fi
  if tool_usable assetfinder --help; then
    launch_enum assetfinder assetfinder --subs-only "$DOMAIN"
  else
    warn "assetfinder unusable or missing"
  fi
  if tool_usable findomain --version; then
    launch_enum findomain findomain -t "$DOMAIN" -q
  else
    warn "findomain unusable or missing"
  fi
  if [ "$RUN_AMASS" -eq 1 ]; then
    if tool_usable amass -version; then
      # Passive only: active amass is slow and noisy.
      launch_enum amass amass enum -passive -d "$DOMAIN" -silent
    else
      warn "amass unusable or missing"
    fi
  fi

  for pid in "${pids[@]:-}"; do
    [ -n "$pid" ] && wait "$pid" 2>/dev/null
  done

  # Keep only hostnames that belong to the target. amass and friends print
  # progress and error text on stdout, which would otherwise be treated as hosts.
  domain_re=$(printf '%s' "$DOMAIN" | sed 's/\./\\./g')
  for f in "$enum_dir"/*.txt; do
    [ -e "$f" ] || continue
    name=$(basename "$f" .txt)
    raw=$(wc -l < "$f" | tr -d ' ')
    grep -E '^[a-z0-9_]([a-z0-9._-]*[a-z0-9])?$' "$f" \
      | grep -E "(^|\.)${domain_re}$" >> "$SUBS" || true
    # grep -c prints 0 and exits 1 on no match; keep the number, drop the status.
    kept=$(grep -cE "(^|\.)${domain_re}$" "$f" 2>/dev/null || true)
    ok "$name: ${kept:-0} host(s) (raw output $raw lines)"
  done
  rm -rf "$enum_dir"

  # The apex is always part of the scope.
  echo "$DOMAIN" >> "$SUBS"

  # Deduplicate the raw pile; palm normalises each entry again when it reads it.
  sort -u "$SUBS" -o "$SUBS"

  count=$(wc -l < "$SUBS" | tr -d ' ')
  [ "$count" -gt 0 ] || die "no subdomains found for $DOMAIN"
  ok "enum: $count unique hosts"
fi

# ----------------------------------------------------------------- 2. dns ----
if stage_done "$RESOLVED"; then
  ok "dns: reusing $RESOLVED ($(wc -l < "$RESOLVED" | tr -d ' ') hosts)"
else
  log "2/6 resolving hosts with palm (wildcards filtered)"
  # -wildcard marks hosts that only exist because of a wildcard record; -fw
  # drops them so later stages do not waste requests on invented names.
  "$PALM_BIN" -l "$SUBS" -mode dns -status -wildcard -fw \
      -c "$CONCURRENCY" -timeout "$TIMEOUT" \
      | awk '{print $1}' | sort -u > "$RESOLVED"
  ok "dns: $(wc -l < "$RESOLVED" | tr -d ' ') hosts resolve"
fi

# ---------------------------------------------------------------- 3. live ----
if stage_done "$LIVE"; then
  ok "live: reusing $LIVE ($(wc -l < "$LIVE" | tr -d ' ') URLs)"
else
  log "3/6 probing HTTP with palm"
  palm_args=(-l "$RESOLVED" -json -status -title -server -tls
             -c "$CONCURRENCY" -timeout "$TIMEOUT")
  [ "$RUN_TAKEOVER" -eq 1 ] && palm_args+=(-takeover)
  [ "$RATE" != "0" ] && palm_args+=(-rate "$RATE")
  # -waf arrived in palm 0.7.0. Probing the help text keeps an older installed
  # palm working (it would otherwise reject the flag and the whole stage fails).
  if palm_supports -waf; then
    palm_args+=(-waf)
  fi

  "$PALM_BIN" "${palm_args[@]}" > "$LIVE_JSON" 2>/dev/null

  # Only live hosts, with the scheme palm decided on.
  grep -o '"probed_url":"[^"]*"' "$LIVE_JSON" 2>/dev/null \
    | sed 's/.*:"//; s/"$//' | sort -u > "$LIVE"

  # palm already fingerprints the edge device from the probe it made, so the
  # WAF stage has a free first pass even if wafw00f is not installed.
  grep -o '"host":"[^"]*"\|"waf":"[^"]*"' "$LIVE_JSON" 2>/dev/null \
    | paste - - 2>/dev/null \
    | sed 's/"host":"\([^"]*\)"\s*"waf":"\([^"]*\)"/\1\thttps:\/\/\1\t\2/' \
    > "$OUTDIR/.waf-palm.txt" || true

  ok "live: $(wc -l < "$LIVE" | tr -d ' ') web endpoints"
fi

# -------------------------------------------------------------- 4. params ----
if [ "$RUN_PARAMS" -eq 0 ]; then
  warn "params: skipped (--no-params)"
elif stage_done "$PARAMS"; then
  ok "params: reusing $PARAMS"
else
  log "4/6 collecting URLs with parameters"
  : > "$PARAMS"

  if have katana; then
    ( cd "$SCRATCH" && timeout "$SRC_TIMEOUT" katana -list "$LIVE" -silent -jc -d 2 -c "$CONCURRENCY" \
        -timeout "$TIMEOUT" </dev/null 2>/dev/null \
        | grep '?' >> "$PARAMS" ) || true
    ok "katana: $(grep -c '?' "$PARAMS" 2>/dev/null || true) URLs"
  else
    warn "katana missing, cannot crawl"
  fi

  # gau/waybackurls surface historical URLs, which often hold parameters that
  # are no longer linked from the site. They are network heavy, so --no-history
  # turns them off while keeping the katana crawl.
  if [ "$RUN_HISTORY" -eq 1 ] && have gau; then
    ( cd "$SCRATCH" && timeout "$SRC_TIMEOUT" sh -c "printf '%s\n' '$DOMAIN' | gau --threads 5" \
        </dev/null 2>/dev/null | grep '?' >> "$PARAMS" ) || true
    ok "gau: added historical URLs"
  fi
  if [ "$RUN_HISTORY" -eq 1 ] && have waybackurls; then
    ( cd "$SCRATCH" && timeout "$SRC_TIMEOUT" sh -c "printf '%s\n' '$DOMAIN' | waybackurls" \
        </dev/null 2>/dev/null | grep '?' >> "$PARAMS" ) || true
    ok "waybackurls: added historical URLs"
  fi

  sort -u "$PARAMS" -o "$PARAMS"
  # Unique parameter names, for wordlist-style review: everything between ? or &
  # and the first = in each URL.
  awk -F'[?&]' '{ for (i = 2; i <= NF; i++) { split($i, kv, "="); if (kv[1] != "") print kv[1] } }' \
    "$PARAMS" 2>/dev/null | sort -u > "$PARAMS_UNIQ"

  ok "params: $(wc -l < "$PARAMS" | tr -d ' ') URLs, $(wc -l < "$PARAMS_UNIQ" | tr -d ' ') unique names"
fi

# ----------------------------------------------------------------- 5. waf ----
if [ "$RUN_WAF" -eq 0 ]; then
  warn "waf: skipped (--no-waf)"
elif stage_done "$WAF_OUT"; then
  ok "waf: reusing $WAF_OUT"
else
  log "5/6 fingerprinting WAFs"
  palm_waf="$OUTDIR/.waf-palm.txt"
  if have wafw00f; then
    # wafw00f prints a banner to stdout, so ask it to write CSV to a file:
    # url,detected,trigger_url,firewall,manufacturer
    waf_csv="$OUTDIR/.waf.csv"
    ( cd "$SCRATCH" && wafw00f -i "$LIVE" -a -f csv -o "$waf_csv" >/dev/null 2>&1 ) || true
    if [ -s "$waf_csv" ]; then
      # One line per host: the detected firewall, or "none".
      awk -F',' '
        NR == 1 { next }
        {
          url = $1
          fw = $4
          if (fw != "" && fw != "None") { waf[url] = fw }
          else if (!(url in waf)) { waf[url] = "none" }
        }
        END { for (u in waf) print u "\t" waf[u] }
      ' "$waf_csv" | sort > "$WAF_OUT"
      rm -f "$waf_csv"
      behind=$(awk -F'\t' '$2 != "none"' "$WAF_OUT" | wc -l | tr -d ' ')
      ok "waf: $behind of $(wc -l < "$WAF_OUT" | tr -d ' ') hosts behind a WAF"
    else
      warn "wafw00f produced no output"
    fi
  elif [ -s "$palm_waf" ]; then
    # No wafw00f: fall back to what palm saw during the HTTP probe.
    awk -F'\t' '$3 != "" {print $1 "\t" $3}' "$palm_waf" | sort > "$WAF_OUT"
    ok "waf: $(wc -l < "$WAF_OUT" | tr -d ' ') hosts tagged by palm -waf"
  else
    warn "wafw00f missing and palm reported no WAF"
  fi
fi

# -------------------------------------------------------------- 6. nuclei ----
# nuclei's own config can point at a missing or unreadable template directory,
# which makes every scan fail with "no templates provided for scan". Resolve a
# usable template tree first and pass it explicitly with -t.
nuclei_templates_dir() {
  local d
  for d in "$NUCLEI_TEMPLATES" "$HOME/nuclei-templates" "$HOME/.local/nuclei-templates" \
           "/usr/share/nuclei-templates" "/opt/nuclei-templates"; do
    [ -n "$d" ] || continue
    if [ -d "$d" ] && [ -n "$(find "$d" -maxdepth 3 -name '*.yaml' -print -quit 2>/dev/null)" ]; then
      printf '%s' "$d"
      return 0
    fi
  done
  return 1
}

if [ "$RUN_NUCLEI" -eq 1 ]; then
  if ! have nuclei; then
    warn "nuclei: not installed, stage skipped"
  elif ! tpl="$(nuclei_templates_dir)"; then
    warn "nuclei: no template directory found, stage skipped"
    warn "  install them once with:  nuclei -update-templates"
  else
    log "6/6 scanning with nuclei (slow, templates: $tpl)"
    : > "$NUCLEI_OUT"
    ( cd "$SCRATCH" && timeout 3600 nuclei -l "$LIVE" -t "$tpl" \
        -severity critical,high,medium -silent -c 25 -timeout "$TIMEOUT" \
        -o "$NUCLEI_OUT" </dev/null 2>/dev/null ) || true
    found=$(grep -c . "$NUCLEI_OUT" 2>/dev/null || true)
    ok "nuclei: ${found:-0} findings -> $NUCLEI_OUT"
  fi
else
  warn "nuclei: skipped (add --with-nuclei to run a template scan)"
fi

# ---------------------------------------------------------------- 7. report ----
# A shareable HTML report is built from live.jsonl when python3 is available.
# palm already renders HTML for its own runs; this gives the pipeline the same
# artifact without re-scanning.
write_html_report() {
  local jsonl="$1" out="$2" domain="$3"
  command -v python3 >/dev/null 2>&1 || return 1
  python3 - "$jsonl" "$out" "$domain" <<'PY'
import html, json, sys

src, dst, domain = sys.argv[1], sys.argv[2], sys.argv[3]
rows = []
for line in open(src, encoding="utf-8", errors="replace"):
    line = line.strip()
    if not line:
        continue
    try:
        d = json.loads(line)
    except Exception:
        continue
    rows.append(d)

def esc(v):
    return html.escape(str(v)) if v not in (None, "") else ""

body = []
for d in rows:
    target = d.get("probed_url") or d.get("url") or d.get("host", "")
    status = d.get("status_code", "")
    flags = []
    if d.get("takeover"):
        flags.append("takeover=" + str(d.get("takeover_provider", "")))
    if d.get("dangling"):
        flags.append("dangling")
    if d.get("wildcard"):
        flags.append("wildcard")
    if d.get("tls_mismatch"):
        flags.append("tls mismatch")
    cls = "bad" if d.get("takeover") else "warn" if d.get("dangling") else "" if d.get("live") else "dead"
    href = target if target.startswith("http") else "https://" + target
    body.append(
        f'<tr class="{cls}"><td><a href="{esc(href)}">{esc(target)}</a></td>'
        f'<td class="num">{esc(status)}</td><td>{esc(d.get("title"))}</td>'
        f'<td>{esc(d.get("server"))}</td><td>{esc(d.get("waf"))}</td>'
        f'<td>{esc(" ".join(flags))}</td><td>{esc(d.get("error"))}</td></tr>'
    )

page = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>recon: {esc(domain)}</title>
<style>
  body{{font:14px/1.5 -apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:2rem auto;max-width:1200px;padding:0 1rem}}
  h1{{font-size:1.25rem}} table{{border-collapse:collapse;width:100%;margin-top:1rem}}
  th,td{{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #8884;vertical-align:top}}
  td.num{{text-align:right;font-variant-numeric:tabular-nums}}
  tr.bad td{{background:#ef44441f}} tr.warn td{{background:#f59e0b1f}} tr.dead td{{opacity:.55}}
  a{{color:inherit}} .foot{{margin-top:1rem;opacity:.6;font-size:.85rem}}
</style></head><body>
<h1>recon: {esc(domain)}</h1>
<table><thead><tr><th>target</th><th>status</th><th>title</th><th>server</th><th>waf</th><th>flags</th><th>error</th></tr></thead><tbody>
{chr(10).join(body)}
</tbody></table>
<p class="foot">{len(rows)} results · palm recon</p>
</body></html>
"""
open(dst, "w", encoding="utf-8").write(page)
PY
}


log "writing summary"
{
  echo "recon summary: $DOMAIN"
  echo "generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "palm: $($PALM_BIN -version 2>/dev/null)"
  echo
  printf '%-22s %s\n' "subdomains:"    "$(wc -l < "$SUBS" | tr -d ' ')"
  printf '%-22s %s\n' "resolved:"      "$(wc -l < "$RESOLVED" | tr -d ' ')"
  printf '%-22s %s\n' "live endpoints:" "$(wc -l < "$LIVE" | tr -d ' ')"
  [ -s "$PARAMS" ] && printf '%-22s %s\n' "parameter URLs:" "$(wc -l < "$PARAMS" | tr -d ' ')"
  [ -s "$PARAMS_UNIQ" ] && printf '%-22s %s\n' "parameter names:" "$(wc -l < "$PARAMS_UNIQ" | tr -d ' ')"
  [ -s "$WAF_OUT" ] && printf '%-22s %s\n' "behind a WAF:" "$(awk -F'\t' '$2 != "none"' "$WAF_OUT" | wc -l | tr -d ' ')"
  [ -s "$NUCLEI_OUT" ] && printf '%-22s %s\n' "nuclei findings:" "$(wc -l < "$NUCLEI_OUT" | tr -d ' ')"

  if [ -s "$LIVE_JSON" ]; then
    echo
    echo "takeover and dangling candidates:"
    # No jq dependency: the fields are flat and produced by palm itself.
    hits=$(grep -E '"takeover":true|"dangling":true' "$LIVE_JSON" \
      | sed 's/.*"host":"\([^"]*\)".*/  \1/' || true)
    if [ -n "$hits" ]; then
      printf '%s\n' "$hits"
    else
      echo "  none"
    fi

    # CNAME chains expose the infrastructure behind a host, which is often more
    # useful than the live list itself: a third-party CDN, an internal load
    # balancer, or a SaaS provider to look at next.
    echo
    echo "CNAME targets:"
    grep -o '"host":"[^"]*"\|"cname":"[^"]*"' "$LIVE_JSON" \
      | paste - - 2>/dev/null \
      | sed 's/"host":"\([^"]*\)"\s*"cname":"\([^"]*\)"/\1\t\2/' \
      | awk -F'\t' -v domain="$DOMAIN" '
          {
            host = $1
            target = $2
            sub(/\.$/, "", target)
            # LookupCNAME echoes the host back when there is no CNAME record.
            if (target == "" || target == host) next
            if (target ~ ("(^|\\.)" domain "$")) kind = "internal"
            else kind = "EXTERNAL"
            count[target]++
            kindof[target] = kind
            if (!(target in example)) example[target] = host
          }
          END {
            for (t in count) printf "  %-45s %-9s x%d  (e.g. %s)\n", t, kindof[t], count[t], example[t]
          }' | sort -k2,2r -k3,3nr | head -25
  fi

  if [ -s "$WAF_OUT" ]; then
    echo
    echo "WAFs:"
    awk -F'\t' '$2 != "none" {print "  " $1 " -> " $2}' "$WAF_OUT" | head -20 || true
  fi

  if [ -s "$PARAMS_UNIQ" ]; then
    echo
    echo "top parameter names:"
    head -15 "$PARAMS_UNIQ" | sed 's/^/  /'
  fi
} > "$SUMMARY"

elapsed=$(( $(date +%s) - start ))

# Exports are rendered from the JSON palm already produced, so no re-scan.
# palm -render keeps this free of any python dependency.
if [ -s "$LIVE_JSON" ]; then
  for fmt in $EXPORT_FORMATS; do
    case "$fmt" in
      html) out="$REPORT_OUT" ;;
      *)    out="$OUTDIR/results.$fmt" ;;
    esac

    if palm_supports -render; then
      if "$PALM_BIN" -render "$LIVE_JSON" -format "$fmt" -o "$out" 2>/dev/null; then
        ok "export: $out"
        continue
      fi
      warn "export $fmt: palm -render failed"
    fi

    # Older palm: HTML can still be produced by the python fallback.
    if [ "$fmt" = "html" ] && [ "$RUN_REPORT" -eq 1 ]; then
      if write_html_report "$LIVE_JSON" "$out" "$DOMAIN"; then
        ok "report: $out"
        continue
      fi
    fi
    warn "export $fmt: skipped (needs palm 0.7.1 or newer, or python3 for html)"
  done
fi

# Scratch space is only needed while the stages run; keep the output folder tidy.
rm -rf "$SCRATCH" 2>/dev/null || true
log "done in ${elapsed}s -> $SUMMARY"
cat "$SUMMARY"
