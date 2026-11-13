#!/usr/bin/env bash
# Run with: bash setup.sh [--install-system] [--no-run|--run-only] [-- APP_ARGS...]
set -euo pipefail

if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
    printf 'Run this script with bash setup.sh; do not source it.\n' >&2
    return 2
fi

usage() {
    cat <<'HELP'
POLTERHEIST setup for Kali/Debian Linux (Python >= 3.11)

  bash setup.sh                       Create/reuse a venv, install requirements, run
  bash setup.sh --install-system       Also install the listed APT dependencies
  bash setup.sh --no-run               Prepare the environment without starting the app
  bash setup.sh --run-only             Run using the existing venv; no installations
  bash setup.sh -- --iot-scan          Prepare and start IoT discovery directly

Run as your normal user. Only --install-system invokes sudo for APT.
The app uses the venv interpreter directly; activation/deactivation are unnecessary.
HELP
}

install_system=0
run_only=0
no_run=0
app_args=()
while (($#)); do
    case "$1" in
        --install-system) install_system=1 ;;
        --run-only) run_only=1 ;;
        --no-run) no_run=1 ;;
        --help|-h) usage; exit 0 ;;
        --) shift; app_args=("$@"); break ;;
        *) printf 'Unknown option: %s\n' "$1" >&2; usage; exit 2 ;;
    esac
    shift
done
if ((run_only && (install_system || no_run))); then
    printf '%s\n' '--run-only cannot be combined with installation options.' >&2
    exit 2
fi
if [[ "$(uname -s)" != "Linux" ]]; then
    printf 'Run setup.sh in a Kali/Linux terminal. On Windows use the Windows Python venv.\n' >&2
    exit 1
fi
if [[ "$(id -u)" == "0" ]]; then
    printf 'Run setup.sh without sudo. APT can request sudo separately with --install-system.\n' >&2
    exit 1
fi
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
cd -- "$project_dir"
if [[ ! -f script.py || ! -f requirements.txt ]]; then
    printf 'script.py and requirements.txt must be beside setup.sh.\n' >&2
    exit 1
fi

if ((install_system)); then
    command -v apt-get >/dev/null || { printf 'APT is required for --install-system.\n' >&2; exit 1; }
    command -v sudo >/dev/null || { printf 'sudo is required for --install-system.\n' >&2; exit 1; }
    packages=(python3 python3-venv python3-pip iw iproute2 tcpdump network-manager
              wpasupplicant bluez systemd dnsmasq-base nftables nmap arp-scan ffmpeg)
    printf 'Installing system packages via APT: %s\n' "${packages[*]}"
    sudo -- apt-get update
    sudo -- apt-get install -y "${packages[@]}"
fi
command -v python3 >/dev/null || { printf 'Install Python 3 with --install-system.\n' >&2; exit 1; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else "Python 3.11 or newer is required")'

# Reuse a Linux environment already used by the project; preserve Windows copies.
env_dir="$project_dir/venv"
for candidate in venv .venv .venv-linux venv-linux; do
    if [[ -x "$project_dir/$candidate/bin/python" && -f "$project_dir/$candidate/pyvenv.cfg" ]]; then
        env_dir="$project_dir/$candidate"
        break
    fi
done
if [[ -f "$env_dir/Scripts/python.exe" && ! -x "$env_dir/bin/python" ]]; then
    env_dir="$project_dir/venv-linux"
fi
env_python="$env_dir/bin/python"
if [[ ! -x "$env_python" || ! -f "$env_dir/pyvenv.cfg" ]]; then
    if ((run_only)); then
        printf 'No Linux venv found. Run bash setup.sh first.\n' >&2
        exit 1
    fi
    printf 'Creating environment: %s\n' "$env_dir"
    if ! python3 -m venv "$env_dir"; then
        printf 'venv creation failed. On Kali try: bash setup.sh --install-system\n' >&2
        printf 'Alternatively: sudo apt update && sudo apt install python3-venv\n' >&2
        exit 1
    fi
fi
"$env_python" -c 'import sys; sys.exit("Refusing to install into the system Python" if sys.prefix == sys.base_prefix else ("The existing venv needs Python 3.11 or newer" if sys.version_info < (3, 11) else 0))'
if ((!run_only)); then
    "$env_python" -m pip --version >/dev/null || {
        printf 'pip is missing in this venv. Install python3-venv, then repair this environment.\n' >&2
        exit 1
    }
    "$env_python" -m pip install --disable-pip-version-check --timeout 30 --retries 2 -r "$project_dir/requirements.txt"
fi
printf 'Environment ready: %s\n' "$env_dir"
printf 'Next run: bash %q --run-only\n' "$project_dir/setup.sh"
printf 'Manual activation, if wanted: source %q\n' "$env_dir/bin/activate"
printf 'Only for workflows that require root: sudo -- %q %q\n' "$env_python" "$project_dir/script.py"
if ((no_run)); then
    exit 0
fi
exec "$env_python" "$project_dir/script.py" "${app_args[@]}"
