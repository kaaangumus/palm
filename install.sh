#!/usr/bin/env sh
set -eu

repo="kaaangumus/palm"
bin_name="palm"
install_dir="${PALM_INSTALL_DIR:-/usr/local/bin}"

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
  download() {
    curl -fsSL "$1" -o "$2"
  }
elif command -v wget >/dev/null 2>&1; then
  download() {
    wget -qO "$2" "$1"
  }
else
  echo "missing required command: curl or wget" >&2
  exit 1
fi

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
url="https://github.com/${repo}/releases/latest/download/${asset}"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

echo "downloading ${asset}"
download "$url" "$tmpdir/$bin_name"
chmod +x "$tmpdir/$bin_name"

if [ ! -d "$install_dir" ]; then
  run_root mkdir -p "$install_dir"
fi

if [ -w "$install_dir" ]; then
  mv "$tmpdir/$bin_name" "$install_dir/$bin_name"
else
  run_root mv "$tmpdir/$bin_name" "$install_dir/$bin_name"
fi

echo "installed: $install_dir/$bin_name"
if command -v "$bin_name" >/dev/null 2>&1; then
  "$bin_name" -version
else
  echo "warning: $install_dir is not in PATH" >&2
  echo "run it directly with: $install_dir/$bin_name" >&2
fi
