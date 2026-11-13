"""Execute setup.sh with SIMULATED tools: no APT, pip or real venv installation."""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash") or (
    "C:/Program Files/Git/bin/bash.exe"
    if Path("C:/Program Files/Git/bin/bash.exe").exists()
    else None
)


@unittest.skipUnless(BASH, "Bash is unavailable")
class SetupTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.root = self.base / "project with spaces"
        self.root.mkdir()
        shutil.copyfile(ROOT / "setup.sh", self.root / "setup.sh")
        (self.root / "POLTERHEIST.py").write_text("# SIMULATED LAUNCHER\n", encoding="utf-8")
        (self.root / "script.py").write_text("# SIMULATED APP\n", encoding="utf-8")
        (self.root / "requirements.txt").write_text("# SIMULATED requirements\n", encoding="utf-8")
        self.bin = self.base / "fake-tools"
        self.bin.mkdir()
        self.log = self.base / "commands.txt"
        self.venv_stub = self.base / "venv-python-stub"
        self.activation_stub = self.base / "venv-activation-stub"
        self.write(
            self.activation_stub,
            """# SIMULATED venv activation, sourced by a real interactive Bash.
export VIRTUAL_ENV="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
_OLD_VIRTUAL_PATH="$PATH"
export PATH="$VIRTUAL_ENV/bin:$PATH"
PS1="(venv) $ "
deactivate() { export PATH="$_OLD_VIRTUAL_PATH"; unset VIRTUAL_ENV; }
""",
        )
        self.write(
            self.venv_stub,
            """#!/usr/bin/env bash
printf 'venv-python %s\\n' "$*" >> "$SETUP_LOG"
if [[ "$*" == '-m pip install '* && "${SIMULATED_PIP_FAIL:-0}" == 1 ]]; then exit 7; fi
if [[ "$*" == '-m pip --version' && "${SIMULATED_PIP_MISSING:-0}" == 1 ]]; then exit 1; fi
if [[ "$*" == '-m ensurepip --upgrade' && "${SIMULATED_ENSUREPIP_FAIL:-0}" == 1 ]]; then exit 9; fi
if [[ "$*" == '-m pip check' && "${SIMULATED_PIP_CHECK_FAIL:-0}" == 1 ]]; then exit 1; fi
exit 0
""",
        )
        self.write(
            self.bin / "python3",
            """#!/usr/bin/env bash
printf 'python3 %s\\n' "$*" >> "$SETUP_LOG"
if [[ "${1:-}" == -m && "${2:-}" == venv ]]; then
    if [[ "${SIMULATED_VENV_FAIL:-0}" == 1 ]]; then exit 8; fi
    mkdir -p "$3/bin"
    cp "$VENV_STUB" "$3/bin/python"
    cp "$ACTIVATION_STUB" "$3/bin/activate"
    chmod +x "$3/bin/python"
    printf 'home = SIMULATED\\n' > "$3/pyvenv.cfg"
fi
""",
        )
        self.write(
            self.bin / "uname", '#!/usr/bin/env bash\nprintf "%s\\n" "${SIMULATED_OS:-Linux}"\n'
        )
        self.write(
            self.bin / "id", '#!/usr/bin/env bash\nprintf "%s\\n" "${SIMULATED_UID:-1000}"\n'
        )
        self.write(
            self.bin / "sudo",
            """#!/usr/bin/env bash
printf 'sudo %s\\n' "$*" >> "$SETUP_LOG"
if [[ "$1" == -H ]]; then shift 4; exec "$@"; fi
if [[ "${SIMULATED_APT_FAIL:-0}" == 1 ]]; then exit 42; fi
""",
        )
        self.write(
            self.bin / "apt-get",
            '#!/usr/bin/env bash\nprintf "apt-get %s\\n" "$*" >> "$SETUP_LOG"\n',
        )
        self.env = dict(
            os.environ,
            SETUP_LOG=self.log.as_posix(),
            VENV_STUB=self.venv_stub.as_posix(),
            ACTIVATION_STUB=self.activation_stub.as_posix(),
        )
        self.env.pop("SUDO_USER", None)

    def write(self, path, content):
        path.write_text(content, encoding="utf-8", newline="\n")
        path.chmod(0o755)

    def run_setup(self, *args, input=None):
        # Git Bash prepends its own utilities at startup. Prepend the test tools
        # inside Bash so real uname/id/sudo cannot shadow these fixtures.
        tool_path = self.bin.as_posix()
        if os.name == "nt":
            tool_path = "/" + tool_path[0].lower() + tool_path[2:]
        return subprocess.run(
            [
                BASH,
                "-c",
                'export PATH="$1:$PATH"; shift; exec bash "$@"',
                "setup-test",
                tool_path,
                (self.root / "setup.sh").as_posix(),
                *args,
            ],
            cwd=self.base,
            env=self.env,
            input=input,
            capture_output=True,
            text=True,
            timeout=15,
        )

    def commands(self):
        return self.log.read_text(encoding="utf-8") if self.log.exists() else ""

    def seed_environment(self, name="venv"):
        folder = self.root / name
        (folder / "bin").mkdir(parents=True)
        shutil.copyfile(self.venv_stub, folder / "bin/python")
        (folder / "bin/python").chmod(0o755)
        (folder / "pyvenv.cfg").write_text("SIMULATED", encoding="utf-8")
        shutil.copyfile(self.activation_stub, folder / "bin/activate")

    def test_default_installs_system_and_requirements_without_starting_app(self):
        result = self.run_setup()
        self.assertEqual(result.returncode, 0, result.stderr)
        commands = self.commands()
        self.assertIn("python3 -m venv ", commands)
        self.assertIn("venv-python -m pip install", commands)
        self.assertIn("-r ", commands)
        self.assertIn("/requirements.txt", commands)
        self.assertIn("venv-python -m pip check", commands)
        self.assertIn("sudo -- apt-get install -y", commands)
        self.assertNotIn("/POLTERHEIST.py", commands)
        self.assertIn("Next run: python3", result.stdout)
        self.assertIn("POLTERHEIST.py", result.stdout)
        self.assertNotIn("Opening Bash", result.stdout)

    def test_prepared_shell_activates_venv_and_can_run_python_and_deactivate(self):
        result = self.run_setup(
            "--shell",
            input="""printf 'ACTIVE=%s\\nCWD=%s\\nPYTHON=%s\\nPROMPT=%s\\n' "$VIRTUAL_ENV" "$PWD" "$(command -v python)" "$PS1"
python POLTERHEIST.py --version
deactivate
printf 'AFTER=%s\\n' "${VIRTUAL_ENV-unset}"
exit
""",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Opening Bash", result.stdout)
        values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        self.assertTrue(values["ACTIVE"].endswith("/project with spaces/venv"), values)
        self.assertEqual(values["CWD"], values["ACTIVE"].removesuffix("/venv"))
        self.assertEqual(values["PYTHON"], values["ACTIVE"] + "/bin/python")
        self.assertIn("(venv)", values["PROMPT"])
        self.assertEqual(values["AFTER"], "unset")
        self.assertIn("venv-python POLTERHEIST.py --version", self.commands())

    def test_sudo_prepared_shell_returns_to_original_user_before_activation(self):
        self.env.update(SIMULATED_UID="0", SUDO_USER="lab-user")
        result = self.run_setup("--shell", input='printf "ACTIVE=%s\\n" "$VIRTUAL_ENV"\nexit\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r"(?m)^ACTIVE=.*/project with spaces/venv$")
        self.assertIn("sudo -H -u lab-user -- bash --noprofile --rcfile ", self.commands())
        self.assertIn("/venv/bin/activate -i", self.commands())

    def test_no_shell_installs_and_returns_without_consuming_commands(self):
        result = self.run_setup("--no-shell", input="echo UNEXPECTED_SHELL_COMMAND\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("Opening Bash", result.stdout)
        self.assertNotIn("UNEXPECTED_SHELL_COMMAND", result.stdout)
        self.assertIn("source ", result.stdout)

    def test_installation_failure_never_opens_a_prepared_shell(self):
        self.env["SIMULATED_PIP_FAIL"] = "1"
        result = self.run_setup("--shell", input="echo UNEXPECTED_SHELL_COMMAND\n")
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertNotIn("Opening Bash", result.stdout)
        self.assertNotIn("UNEXPECTED_SHELL_COMMAND", result.stdout)

    def test_run_option_and_application_arguments_launch_after_installation(self):
        for args in (("--run",), ("--", "--iot-scan")):
            with self.subTest(args=args):
                self.log.write_text("", encoding="utf-8")
                result = self.run_setup("--skip-system", *args)
                self.assertEqual(result.returncode, 0, result.stderr)
                commands = self.commands()
                self.assertIn("/POLTERHEIST.py", commands)
                self.assertLess(commands.index("-m pip check"), commands.index("/POLTERHEIST.py"))
                self.assertNotIn("sudo ", commands)
                if "--iot-scan" in args:
                    self.assertIn("POLTERHEIST.py --iot-scan", commands)

    def test_second_run_reuses_environment_without_recreation(self):
        self.seed_environment()
        result = self.run_setup("--no-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("-m venv", self.commands())
        self.assertNotIn("/POLTERHEIST.py", self.commands())
        self.assertIn("venv-python -m pip install", self.commands())

    def test_reuses_existing_project_dot_venv(self):
        self.seed_environment(".venv")
        result = self.run_setup("--run-only", "--", "--iot-scan")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("/.venv", result.stdout)
        self.assertNotIn("-m pip", self.commands())
        self.assertNotIn("-m venv", self.commands())
        self.assertNotIn("apt-get", self.commands())
        self.assertIn("POLTERHEIST.py --iot-scan", self.commands())

    def test_windows_venv_is_preserved_and_linux_sibling_created(self):
        (self.root / "venv/Scripts").mkdir(parents=True)
        original = self.root / "venv/Scripts/python.exe"
        original.write_bytes(b"SIMULATED WINDOWS ENV")
        result = self.run_setup("--no-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(original.read_bytes(), b"SIMULATED WINDOWS ENV")
        self.assertTrue((self.root / "venv-linux/bin/python").exists())

    def test_legacy_options_still_work_and_pip_never_uses_root_sudo(self):
        result = self.run_setup("--install-system", "--no-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        commands = self.commands()
        self.assertIn("sudo -- apt-get update", commands)
        self.assertIn("sudo -- apt-get install -y python3", commands)
        self.assertIn("bluez", commands)
        self.assertNotIn("sudo pip", commands)
        self.assertNotIn("sudo -- python", commands)

    def test_pip_failure_does_not_start_application(self):
        self.env["SIMULATED_PIP_FAIL"] = "1"
        result = self.run_setup("--run")
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertNotIn("/POLTERHEIST.py", self.commands())
        self.assertNotIn("Environment ready", result.stdout)

    def test_missing_venv_module_reports_repair_without_automatic_apt(self):
        self.env["SIMULATED_VENV_FAIL"] = "1"
        result = self.run_setup("--skip-system")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("python3-venv", result.stderr)
        self.assertNotIn("sudo ", self.commands())

    def test_root_can_install_without_sudo(self):
        self.env["SIMULATED_UID"] = "0"
        result = self.run_setup()
        self.assertEqual(result.returncode, 0, result.stderr)
        commands = self.commands()
        self.assertIn("apt-get update", commands)
        self.assertIn("venv-python -m pip install", commands)
        self.assertNotIn("sudo ", commands)

    def test_sudo_installs_python_packages_and_runs_app_as_original_user(self):
        self.env.update(SIMULATED_UID="0", SUDO_USER="lab-user")
        result = self.run_setup("--run")
        self.assertEqual(result.returncode, 0, result.stderr)
        commands = self.commands()
        self.assertIn("sudo -H -u lab-user -- python3 -m venv", commands)
        for line in commands.splitlines():
            if line.startswith("sudo "):
                self.assertTrue(line.startswith("sudo -H -u lab-user -- "), line)
        self.assertIn("venv-python -m pip install", commands)
        self.assertIn("/POLTERHEIST.py", commands)

    def test_non_linux_is_rejected_before_installation(self):
        self.env["SIMULATED_OS"] = "MINGW64"
        self.assertNotEqual(self.run_setup().returncode, 0)
        self.assertEqual(self.commands(), "")

    def test_run_only_without_environment_makes_no_installations(self):
        result = self.run_setup("--run-only")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("-m venv", self.commands())
        self.assertNotIn("-m pip", self.commands())
        self.assertNotIn("apt-get", self.commands())

    def test_apt_failure_stops_before_python_installation(self):
        self.env["SIMULATED_APT_FAIL"] = "1"
        result = self.run_setup("--run")
        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertNotIn("-m venv", self.commands())
        self.assertNotIn("-m pip", self.commands())
        self.assertNotIn("/POLTERHEIST.py", self.commands())

    def test_missing_pip_is_bootstrapped_inside_existing_environment(self):
        self.seed_environment()
        self.env["SIMULATED_PIP_MISSING"] = "1"
        result = self.run_setup("--skip-system")
        self.assertEqual(result.returncode, 0, result.stderr)
        commands = self.commands()
        self.assertIn("venv-python -m ensurepip --upgrade", commands)
        self.assertIn("venv-python -m pip install", commands)
        self.assertNotIn("-m venv", commands)

    def test_pip_bootstrap_or_dependency_check_failure_does_not_report_ready(self):
        for flags in (
            {"SIMULATED_PIP_MISSING": "1", "SIMULATED_ENSUREPIP_FAIL": "1"},
            {"SIMULATED_PIP_CHECK_FAIL": "1"},
        ):
            with self.subTest(flags=flags):
                self.env.update(flags)
                self.log.write_text("", encoding="utf-8")
                result = self.run_setup("--run")
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("Environment ready", result.stdout)
                self.assertNotIn("/POLTERHEIST.py", self.commands())
                for flag in flags:
                    self.env.pop(flag)

    def test_conflicting_options_fail_before_installation(self):
        for args in (
            ("--run", "--no-run"),
            ("--no-run", "--", "--iot-scan"),
            ("--run-only", "--install-system"),
            ("--run-only", "--no-run"),
            ("--shell", "--run"),
            ("--shell", "--run-only"),
            ("--shell", "--", "--iot-scan"),
        ):
            with self.subTest(args=args):
                self.assertEqual(self.run_setup(*args).returncode, 2)
                self.assertEqual(self.commands(), "")


@unittest.skipUnless(sys.platform.startswith("linux"), "Requires real Linux venv activation")
class LinuxActivationTests(unittest.TestCase):
    def test_setup_in_terminal_leaves_real_venv_active_without_manual_commands(self):
        import pty
        import select
        import time

        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "project with spaces"
            project.mkdir()
            shutil.copyfile(ROOT / "setup.sh", project / "setup.sh")
            (project / "script.py").touch()
            (project / "POLTERHEIST.py").touch()
            # Exercise real venv/pip without downloading any packages or using APT.
            (project / "requirements.txt").write_text("# No external test dependencies\n")
            environment = dict(os.environ, PIP_NO_INDEX="1", PIP_CONFIG_FILE=os.devnull)
            for name in ("SUDO_USER", "PYTHONHOME", "PYTHONPATH", "VIRTUAL_ENV_DISABLE_PROMPT"):
                environment.pop(name, None)
            master, slave = pty.openpty()
            try:
                process = subprocess.Popen(
                    [BASH, str(project / "setup.sh"), "--skip-system"],
                    stdin=slave,
                    stdout=slave,
                    stderr=slave,
                    cwd=directory,
                    env=environment,
                )
                try:
                    output = b""
                    sent = False
                    deadline = time.monotonic() + 45
                    while time.monotonic() < deadline:
                        if select.select([master], [], [], 0.1)[0]:
                            output += os.read(master, 65536)
                        if b"Ready to use: python3 POLTERHEIST.py" in output and not sent:
                            os.write(
                                master,
                                b'python -c \'import os, sys; print("ACTIVE_PREFIX=" + sys.prefix); print("ACTIVE_ENV=" + os.environ["VIRTUAL_ENV"])\'\nexit\n',
                            )
                            sent = True
                        if process.poll() is not None and not select.select([master], [], [], 0)[0]:
                            break
                    self.assertEqual(process.poll(), 0, output.decode(errors="replace"))
                    expected = str(project / "venv").encode()
                    self.assertIn(b"ACTIVE_PREFIX=" + expected, output)
                    self.assertIn(b"ACTIVE_ENV=" + expected, output)
                    self.assertIn(b"(venv)", output)
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=5)
            finally:
                os.close(master)
                os.close(slave)


if __name__ == "__main__":
    unittest.main()
