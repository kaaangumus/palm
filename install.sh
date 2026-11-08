#!/usr/bin/env sh
set -eu

repo="kaaangumus/palm"
bin_name="palm"
install_dir="${PALM_INSTALL_DIR:-/usr/local/bin}"
version="${PALM_VERSION:-latest}"
download_mode="${PALM_DOWNLOAD_MODE:-auto}"

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

need uname
need mktemp

run_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    echo "need permission for $install_dir and sudo is not installed" >&2
    echo "try: PALM_INSTALL_DIR=\"\$HOME/.local/bin\" sh install.sh" >&2
    exit 1
  fi
}

if command -v curl >/dev/null 2>&1; then
  fetcher="curl"
elif command -v wget >/dev/null 2>&1; then
  fetcher="wget"
else
  echo "missing required command: curl or wget" >&2
  exit 1
fi

# fetch URL DEST [accept-header]
fetch() {
  if [ "$fetcher" = "curl" ]; then
    if [ -n "${3:-}" ]; then
      curl -fsSL --retry 3 --retry-delay 2 --retry-all-errors -H "$3" "$1" -o "$2"
    else
      curl -fsSL --retry 3 --retry-delay 2 --retry-all-errors "$1" -o "$2"
    fi
  else
    if [ -n "${3:-}" ]; then
      wget -qO "$2" --tries=3 --waitretry=2 --header="$3" "$1"
    else
      wget -qO "$2" --tries=3 --waitretry=2 "$1"
    fi
  fi
}

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"

case "$os" in
  linux) goos="linux" ;;
  darwin) goos="darwin" ;;
  *)
    echo "unsupported OS: $os" >&2
    exit 1
    ;;
esac

case "$arch" in
  x86_64|amd64) goarch="amd64" ;;
  aarch64|arm64) goarch="arm64" ;;
  *)
    echo "unsupported architecture: $arch" >&2
    exit 1
    ;;
esac

asset="${bin_name}_${goos}_${goarch}"

if [ "$version" = "latest" ]; then
  direct_url="https://github.com/${repo}/releases/latest/download/${asset}"
  release_api="https://api.github.com/repos/${repo}/releases/latest"
  tag="latest"
else
  case "$version" in
    v*) tag="$version" ;;
    *) tag="v$version" ;;
  esac
  direct_url="https://github.com/${repo}/releases/download/${tag}/${asset}"
  release_api="https://api.github.com/repos/${repo}/releases/tags/${tag}"
fi

checksums_url="${direct_url%/*}/checksums.txt"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
out="$tmpdir/$bin_name"

# GitHub's release CDN answers 504 for some networks while the API still serves
# the asset. Three paths are tried in order, and each downloaded file is checked
# before it is accepted; the API is used with Accept: application/octet-stream so
# it streams the same bytes instead of a JSON document.
download_via_api() {
  release_json="$tmpdir/release.json"
  echo "resolving ${asset} through the GitHub API"
  if ! fetch "$release_api" "$release_json"; then
    echo "could not read release metadata: $release_api" >&2
    return 1
  fi

  asset_id="$(awk -v want="$asset" '
    /"id":/   { if (match($0, /"id":[ ]*[0-9]+/)) { id = substr($0, RSTART, RLENGTH); gsub(/[^0-9]/, "", id) } }
    /"name":/ { if (index($0, "\"" want "\"") && id != "") { print id; exit } }
  ' "$release_json")"

  if [ -z "$asset_id" ]; then
    echo "release metadata has no asset named $asset" >&2
    return 1
  fi

  fetch "https://api.github.com/repos/${repo}/releases/assets/${asset_id}" "$out" \
    "Accept: application/octet-stream"
}

# A logged-in gh CLI uses an authenticated API request, which keeps working when
# anonymous API calls are rate limited or degraded.
download_via_gh() {
  if ! command -v gh >/dev/null 2>&1; then
    return 1
  fi
  gh_target="$asset"
  if [ "$goos" = "windows" ]; then
    gh_target="${asset}.exe"
  fi
  echo "resolving ${asset} through the gh CLI"
  if ! gh release download "$tag" --repo "$repo" --pattern "$gh_target" --output "$out" --clobber >&2; then
    return 1
  fi
}

verify_binary() {
  size="$(wc -c < "$1" | tr -d ' ')"
  if [ "${size:-0}" -lt 1000000 ]; then
    echo "downloaded file is too small (${size:-0} bytes); likely an error page" >&2
    return 1
  fi
  magic="$(od -An -tx1 -N4 "$1" | tr -d ' \n')"
  case "$goos" in
    linux)
      if [ "$magic" != "7f454c46" ]; then
        echo "downloaded file is not a Linux executable (magic $magic)" >&2
        return 1
      fi
      ;;
    darwin)
      case "$magic" in
        cffaedfe|cefaedfe|feedface|feedfacf|cafebabe|cafebabf) ;;
        *)
          echo "downloaded file is not a macOS executable (magic $magic)" >&2
          return 1
          ;;
      esac
      ;;
  esac
  return 0
}

# Older releases predate checksums.txt; verification is skipped (with a
# warning) when the file or the asset entry is missing, but a mismatch fails.
verify_checksum() {
  sums="$tmpdir/checksums.txt"
  if ! fetch "$checksums_url" "$sums" 2>/dev/null; then
    echo "warning: checksum file not available, skipping verification" >&2
    return 0
  fi
  expected="$(awk -v want="$asset" '$2 == want { print $1; exit }' "$sums")"
  if [ -z "$expected" ]; then
    echo "warning: no checksum for $asset, skipping verification" >&2
    return 0
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$out" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$out" | awk '{print $1}')"
  else
    echo "warning: sha256sum/shasum not found, skipping verification" >&2
    return 0
  fi
  if [ "$actual" != "$expected" ]; then
    echo "checksum mismatch for $asset" >&2
    echo "expected $expected" >&2
    echo "got      $actual" >&2
    return 1
  fi
  echo "checksum verified"
  return 0
}

echo "downloading ${asset}"
downloaded=0

if [ "$download_mode" != "api" ] && [ "$download_mode" != "gh" ]; then
  if fetch "$direct_url" "$out" && verify_binary "$out"; then
    downloaded=1
  else
    echo "direct download failed, trying another source" >&2
  fi
fi

if [ "$downloaded" -eq 0 ] && [ "$download_mode" != "api" ]; then
  if download_via_gh && verify_binary "$out"; then
    downloaded=1
  else
    echo "gh CLI path failed, trying the GitHub API" >&2
  fi
fi

if [ "$downloaded" -eq 0 ]; then
  if ! download_via_api; then
    echo "download failed." >&2
    echo "try again in a moment, or install with Go: go install github.com/${repo}@latest" >&2
    exit 1
  fi
fi

if ! verify_binary "$out"; then
  echo "download failed." >&2
  echo "try again in a moment, or install with Go: go install github.com/${repo}@latest" >&2
  exit 1
fi

if ! verify_checksum; then
  echo "download verification failed." >&2
  exit 1
fi

chmod +x "$out"

if [ ! -d "$install_dir" ]; then
  run_root mkdir -p "$install_dir"
fi

if [ -w "$install_dir" ]; then
  mv "$out" "$install_dir/$bin_name"
else
  run_root mv "$out" "$install_dir/$bin_name"
fi

echo "installed: $install_dir/$bin_name"
if command -v "$bin_name" >/dev/null 2>&1; then
  "$bin_name" -version
else
  echo "warning: $install_dir is not in PATH" >&2
  echo "run it directly with: $install_dir/$bin_name" >&2
fi
