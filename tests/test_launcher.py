"""Launcher regressions; no discovery or real network operations."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import POLTERHEIST as launcher
import script


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.project = (
            Path(self.enterContext(tempfile.TemporaryDirectory())) / "project with spaces"
        )
        self.project.mkdir()
        self.entry = self.project / "POLTERHEIST.py"
        self.enterContext(patch.object(launcher, "__file__", str(self.entry)))
        self.enterContext(patch.object(launcher.sys, "platform", "linux"))

    def seed_environment(self, name):
        environment = self.project / name
        (environment / "bin").mkdir(parents=True)
        (environment / "pyvenv.cfg").write_text("# SIMULATED\n", encoding="utf-8")
        python = environment / "bin/python"
        python.touch()
        python.chmod(0o755)
        return environment, python

    def test_system_python_reexecutes_with_project_python_and_preserves_arguments(self):
        _, python = self.seed_environment("venv")
        arguments = ["--ssid", "Lab ' & $()", "--bssid", "02:00:00:00:00:01"]
        with (
            patch.object(launcher.os, "execv", side_effect=SystemExit(23)) as execute,
            patch.object(script, "main") as application,
        ):
            with self.assertRaises(SystemExit) as outcome:
                launcher.main(arguments)
        self.assertEqual(outcome.exception.code, 23)
        execute.assert_called_once_with(str(python), [str(python), str(self.entry), *arguments])
        application.assert_not_called()

    def test_each_supported_environment_is_reused_without_recursive_execution(self):
        for name in ("venv", ".venv", ".venv-linux", "venv-linux"):
            with self.subTest(name=name):
                environment, _ = self.seed_environment(name)
                with (
                    patch.object(launcher.sys, "prefix", str(environment)),
                    patch.object(launcher.os, "execv") as execute,
                    patch.object(script, "main", return_value=17) as application,
                ):
                    self.assertEqual(launcher.main(["--check"]), 17)
                execute.assert_not_called()
                application.assert_called_once_with(["--check"])
                # Only remove the fixture created by this test, inside its temp directory.
                shutil.rmtree(environment)

    def test_windows_environment_is_ignored_in_favour_of_linux_sibling(self):
        (self.project / "venv/Scripts").mkdir(parents=True)
        (self.project / "venv/Scripts/python.exe").touch()
        _, python = self.seed_environment("venv-linux")
        with patch.object(launcher.os, "execv", side_effect=SystemExit(0)) as execute:
            with self.assertRaises(SystemExit):
                launcher.main([])
        self.assertEqual(execute.call_args.args[0], str(python))

    def test_environment_precedence_matches_setup(self):
        _, python = self.seed_environment("venv")
        self.seed_environment(".venv")
        with patch.object(launcher.os, "execv", side_effect=SystemExit(0)) as execute:
            with self.assertRaises(SystemExit):
                launcher.main([])
        self.assertEqual(execute.call_args.args[0], str(python))

    def test_no_environment_preserves_help_and_legacy_setup(self):
        with (
            patch.object(launcher.os, "execv") as execute,
            patch.object(script, "main", return_value=0) as application,
        ):
            self.assertEqual(launcher.main(["--help"]), 0)
        execute.assert_not_called()
        application.assert_called_once_with(["--help"])

    def test_windows_keeps_the_explicit_interpreter(self):
        self.seed_environment("venv")
        with (
            patch.object(launcher.sys, "platform", "win32"),
            patch.object(launcher.os, "execv") as execute,
            patch.object(script, "main", return_value=0),
        ):
            self.assertEqual(launcher.main([]), 0)
        execute.assert_not_called()


@unittest.skipUnless(sys.platform.startswith("linux"), "Requires an actual Linux Python venv")
class LinuxLauncherIntegrationTests(unittest.TestCase):
    def test_fresh_shell_uses_venv_packages_from_another_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "project with spaces"
            project.mkdir()
            entry = project / "POLTERHEIST.py"
            shutil.copyfile(Path(launcher.__file__), entry)
            environment = project / "venv"
            subprocess.run(
                [sys.executable, "-m", "venv", "--without-pip", str(environment)],
                check=True,
                capture_output=True,
                timeout=30,
            )
            site_packages = next((environment / "lib").glob("python*/site-packages"))
            (site_packages / "setup_test_dependency.py").write_text(
                'VALUE = "installed in project venv"\n', encoding="utf-8"
            )
            (project / "script.py").write_text(
                "import json, sys, setup_test_dependency\n"
                "def main(argv):\n"
                "    print(json.dumps([sys.prefix, setup_test_dependency.VALUE, argv]))\n"
                "    return 23\n",
                encoding="utf-8",
            )
            fresh_environment = dict(os.environ)
            for name in ("VIRTUAL_ENV", "PYTHONPATH", "PYTHONHOME"):
                fresh_environment.pop(name, None)
            result = subprocess.run(
                [sys.executable, str(entry), "--ssid", "Lab ' & $()"],
                cwd=directory,
                env=fresh_environment,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(result.returncode, 23, result.stderr)
            prefix, value, args = json.loads(result.stdout)
            self.assertEqual(Path(prefix), environment)
            self.assertEqual(value, "installed in project venv")
            self.assertEqual(args, ["--ssid", "Lab ' & $()"])


if __name__ == "__main__":
    unittest.main()
