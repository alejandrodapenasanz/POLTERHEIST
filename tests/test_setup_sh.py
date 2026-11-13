"""Execute setup.sh with SIMULATED tools: no APT, pip or real venv installation."""

import os
import shutil
import subprocess
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
        (self.root / "script.py").write_text("# SIMULATED APP\n", encoding="utf-8")
        (self.root / "requirements.txt").write_text("# SIMULATED requirements\n", encoding="utf-8")
        self.bin = self.base / "fake-tools"
        self.bin.mkdir()
        self.log = self.base / "commands.txt"
        self.venv_stub = self.base / "venv-python-stub"
        self.write(
            self.venv_stub,
            """#!/usr/bin/env bash
printf 'venv-python %s\\n' "$*" >> "$SETUP_LOG"
if [[ "$*" == '-m pip install '* && "${SIMULATED_PIP_FAIL:-0}" == 1 ]]; then exit 7; fi
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
            self.bin / "sudo", '#!/usr/bin/env bash\nprintf "sudo %s\\n" "$*" >> "$SETUP_LOG"\n'
        )
        self.write(
            self.bin / "apt-get",
            "#!/usr/bin/env bash\nexit 99 # must only be reached through simulated sudo\n",
        )
        self.env = dict(
            os.environ, SETUP_LOG=self.log.as_posix(), VENV_STUB=self.venv_stub.as_posix()
        )

    def write(self, path, content):
        path.write_text(content, encoding="utf-8", newline="\n")
        path.chmod(0o755)

    def run_setup(self, *args):
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

    def test_default_creates_venv_installs_there_and_runs_from_project(self):
        result = self.run_setup("--", "--iot-scan")
        self.assertEqual(result.returncode, 0, result.stderr)
        commands = self.commands()
        self.assertIn("python3 -m venv ", commands)
        self.assertIn("venv-python -m pip install", commands)
        self.assertIn("script.py --iot-scan", commands)
        self.assertNotIn("sudo ", commands)

    def test_second_run_reuses_environment_without_recreation(self):
        self.seed_environment()
        result = self.run_setup("--no-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("-m venv", self.commands())
        self.assertNotIn("/script.py", self.commands())
        self.assertIn("venv-python -m pip install", self.commands())

    def test_reuses_existing_project_dot_venv(self):
        self.seed_environment(".venv")
        result = self.run_setup("--run-only")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("/.venv", result.stdout)
        self.assertNotIn("-m pip", self.commands())
        self.assertNotIn("-m venv", self.commands())

    def test_windows_venv_is_preserved_and_linux_sibling_created(self):
        (self.root / "venv/Scripts").mkdir(parents=True)
        original = self.root / "venv/Scripts/python.exe"
        original.write_bytes(b"SIMULATED WINDOWS ENV")
        result = self.run_setup("--no-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(original.read_bytes(), b"SIMULATED WINDOWS ENV")
        self.assertTrue((self.root / "venv-linux/bin/python").exists())

    def test_system_install_is_explicit_and_pip_never_uses_sudo(self):
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
        result = self.run_setup()
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertNotIn("/script.py", self.commands())

    def test_missing_venv_module_reports_repair_without_automatic_apt(self):
        self.env["SIMULATED_VENV_FAIL"] = "1"
        result = self.run_setup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("python3-venv", result.stderr)
        self.assertNotIn("sudo ", self.commands())

    def test_root_and_non_linux_are_rejected_before_installation(self):
        self.env["SIMULATED_UID"] = "0"
        self.assertNotEqual(self.run_setup().returncode, 0)
        self.assertEqual(self.commands(), "")
        self.env["SIMULATED_UID"] = "1000"
        self.env["SIMULATED_OS"] = "MINGW64"
        self.assertNotEqual(self.run_setup().returncode, 0)
        self.assertEqual(self.commands(), "")

    def test_run_only_without_environment_makes_no_installations(self):
        result = self.run_setup("--run-only")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("-m venv", self.commands())
        self.assertNotIn("-m pip", self.commands())


if __name__ == "__main__":
    unittest.main()
