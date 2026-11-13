#!/usr/bin/env bash
# Run with: bash setup.sh [--skip-system] [--no-shell|--run|--run-only] [-- APP_ARGS...]
set -euo pipefail

if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
    printf 'Run this script with bash setup.sh; do not source it.\n' >&2
    return 2
fi

usage() {
    cat <<'HELP'
POLTERHEIST setup for Kali/Debian/Ubuntu Linux (Python >= 3.11)

  bash setup.sh                       Install everything and open a Bash session with venv active
  bash setup.sh --skip-system          Install only Python requirements (system tools ready)
  bash setup.sh --no-shell             Install and exit (automation; no interactive session)
  bash setup.sh --shell                Open the activated session even without a terminal
  bash setup.sh --run                  Install and start the application
  bash setup.sh --run-only             Start with the existing venv; no installations
  bash setup.sh -- --iot-scan          Install and start IoT discovery directly
  bash setup.sh --no-run               Explicitly request setup only (the default)
  bash setup.sh --install-system       Explicitly request APT dependencies (the default)

APT requests sudo when needed. Python packages stay in the project virtual environment.
After setup, run: python3 POLTERHEIST.py
The prepared session stays in the project directory. Type exit to return to your
previous shell, or deactivate to disable the venv. A child process cannot activate
its parent shell. Without a terminal, setup exits unless --shell is requested.
On other Linux distributions, install system tools yourself and use --skip-system.
HELP
}

install_system=1
system_option=0
run_only=0
no_run=0
run_app=0
shell_mode=auto
app_args=()
while (($#)); do
    case "$1" in
        --install-system) install_system=1; system_option=1 ;;
        --skip-system) install_system=0; system_option=1 ;;
        --run-only) run_only=1 ;;
        --no-run) no_run=1 ;;
        --run) run_app=1 ;;
        --no-shell) shell_mode=never ;;
        --shell) shell_mode=always ;;
        --help|-h) usage; exit 0 ;;
        --) shift; app_args=("$@"); run_app=1; break ;;
        *) printf 'Unknown option: %s\n' "$1" >&2; usage; exit 2 ;;
    esac
    shift
done
if ((run_only && (system_option || no_run))); then
    printf '%s\n' '--run-only cannot be combined with installation options.' >&2
    exit 2
fi
if ((no_run && run_app)); then
    printf '%s\n' '--no-run cannot be combined with --run or application arguments.' >&2
    exit 2
fi
if [[ "$shell_mode" == always ]] && ((run_app || run_only)); then
    printf '%s\n' '--shell cannot be combined with --run, --run-only or application arguments.' >&2
    exit 2
fi
if [[ "$(uname -s)" != "Linux" ]]; then
    printf 'Run setup.sh in a Kali/Linux terminal. On Windows use the Windows Python venv.\n' >&2
    exit 1
fi
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
cd -- "$project_dir"
if [[ ! -f POLTERHEIST.py || ! -f script.py || ! -f requirements.txt ]]; then
    printf 'POLTERHEIST.py, script.py and requirements.txt must be beside setup.sh.\n' >&2
    exit 1
fi

# If invoked with sudo, keep the venv and the application owned by the caller.
user_command=()
root_command=()
if [[ "$(id -u)" == "0" ]]; then
    if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != root ]]; then
        command -v sudo >/dev/null || { printf 'sudo is required to return to %s.\n' "$SUDO_USER" >&2; exit 1; }
        user_command=(sudo -H -u "$SUDO_USER" --)
    fi
else
    root_command=(sudo --)
fi

if ((install_system && !run_only)); then
    command -v apt-get >/dev/null || {
        printf 'Automatic system installation requires APT (Kali/Debian/Ubuntu).\nInstall system tools with your package manager, then use --skip-system.\n' >&2
        exit 1
    }
    if ((${#root_command[@]})); then
        command -v sudo >/dev/null || { printf 'Install sudo or run setup.sh as root.\n' >&2; exit 1; }
    fi
    packages=(python3 python3-venv python3-pip iw iproute2 tcpdump network-manager
              wpasupplicant bluez systemd dnsmasq-base nftables nmap arp-scan ffmpeg)
    printf 'Installing system packages via APT: %s\n' "${packages[*]}"
    "${root_command[@]}" apt-get update
    "${root_command[@]}" apt-get install -y "${packages[@]}"
fi

# Reuse a Linux environment already used by the project; preserve Windows copies.
env_dir="$project_dir/venv"
for candidate in venv .venv .venv-linux venv-linux; do
    if [[ -x "$project_dir/$candidate/bin/python" && -f "$project_dir/$candidate/pyvenv.cfg" ]]; then
        env_dir="$project_dir/$candidate"
        break
    fi
done
if [[ -d "$env_dir/Scripts" && ! -x "$env_dir/bin/python" ]]; then
    env_dir="$project_dir/venv-linux"
fi
env_python="$env_dir/bin/python"
if [[ ! -x "$env_python" || ! -f "$env_dir/pyvenv.cfg" ]]; then
    if ((run_only)); then
        printf 'No Linux venv found. Run bash setup.sh first.\n' >&2
        exit 1
    fi
    command -v python3 >/dev/null || { printf 'Install Python 3.11 or newer, then rerun bash setup.sh.\n' >&2; exit 1; }
    python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else "Python 3.11 or newer is required")'
    if [[ -d "$env_dir/Scripts" ]]; then
        printf 'A Windows environment already occupies %s. Move it aside and rerun setup.\n' "$env_dir" >&2
        exit 1
    fi
    printf 'Creating environment: %s\n' "$env_dir"
    if ! "${user_command[@]}" python3 -m venv "$env_dir"; then
        printf 'venv creation failed. On Kali try: bash setup.sh --install-system\n' >&2
        printf 'Alternatively: sudo apt update && sudo apt install python3-venv\n' >&2
        exit 1
    fi
fi
"${user_command[@]}" "$env_python" -c 'import sys; sys.exit("Refusing to install into the system Python" if sys.prefix == sys.base_prefix else ("The existing venv needs Python 3.11 or newer; move it aside and rerun setup" if sys.version_info < (3, 11) else 0))'
if ((!run_only)); then
    if ! "${user_command[@]}" "$env_python" -m pip --version >/dev/null 2>&1; then
        if ! "${user_command[@]}" "$env_python" -m ensurepip --upgrade; then
            printf 'pip is missing. Install python3-venv, move this environment aside and rerun setup.\n' >&2
            exit 1
        fi
    fi
    "${user_command[@]}" "$env_python" -m pip install --disable-pip-version-check --timeout 30 --retries 2 -r "$project_dir/requirements.txt"
    "${user_command[@]}" "$env_python" -m pip check
fi
printf 'Environment ready: %s\n' "$env_dir"
printf 'Next run: python3 %q\n' "$project_dir/POLTERHEIST.py"
printf 'Only for workflows that require root: sudo -- %q %q\n' "$env_python" "$project_dir/POLTERHEIST.py"
if ((run_app || run_only)); then
    exec "${user_command[@]}" "$env_python" "$project_dir/POLTERHEIST.py" "${app_args[@]}"
fi

# Executing a script cannot change its parent's PATH or VIRTUAL_ENV. Replace
# this process with an interactive Bash that sources the venv's activation
# script as its rcfile, after sudo has returned to the original user.
if [[ "$shell_mode" == always || ( "$shell_mode" == auto && -t 0 && -t 1 ) ]]; then
    if [[ ! -r "$env_dir/bin/activate" ]]; then
        printf 'The venv activation script is missing: %s/bin/activate\n' "$env_dir" >&2
        exit 1
    fi
    printf '\nOpening Bash with the venv activated in %s\n' "$project_dir"
    printf 'Ready to use: python3 POLTERHEIST.py\nType exit to return to your previous shell.\n\n'
    exec "${user_command[@]}" bash --noprofile --rcfile "$env_dir/bin/activate" -i
fi
printf 'To activate in your current shell: source %q\n' "$env_dir/bin/activate"
