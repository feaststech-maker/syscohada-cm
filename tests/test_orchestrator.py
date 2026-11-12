"""Installer contract tests. Every server process is mocked or strictly read-only.

The real install entry point is never run against this machine's filesystem.
All paths are injected into TemporaryDirectory; no apt, systemctl or SSH runs.
"""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

KIT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KIT / "lib"))
import deploylib as lib


def import_installer(name="syscohada_deployment_under_test"):
    spec = importlib.util.spec_from_file_location(name, KIT / "bin/deploy.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


deploy = import_installer()


def config(**changes):
    value = {"domain": "dsf.example.com", "email": "admin@example.com", "company": "Société de test",
             "expected_ipv4": "93.184.216.34", "accept_acme_terms": True}
    value.update(changes)
    return value


class ReadOnlyRunner:
    """Reject any unexpected command rather than accidentally executing one."""
    def __init__(self, addresses=None, tmpfs=True):
        self.secrets = []
        self.commands = []
        self.addresses = addresses if addresses is not None else ["93.184.216.34"]
        self.tmpfs = tmpfs

    def run(self, argv, **options):
        self.commands.append((argv, options))
        if argv == ["ip", "-j", "address", "show", "scope", "global"]:
            output = json.dumps([{"addr_info": [{"local": ip} for ip in self.addresses]}])
        elif argv == ["findmnt", "-n", "-o", "FSTYPE", "--target", "/run"]:
            output = "tmpfs\n" if self.tmpfs else "ext4\n"
        elif argv == ["ss", "-H", "-ltn"]:
            output = ""
        else:
            raise AssertionError("Unexpected process in read-only test: " + repr(argv))
        return subprocess.CompletedProcess(argv, 0, output, "")


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.folder = Path(self.temporary.name)
        self.system = self.folder / "vps"
        self.kit = self.folder / "kit"
        self.paths = deploy.DeployPaths(kit=self.kit, system=self.system)
        (self.system / "etc").mkdir(parents=True)
        (self.system / "etc/os-release").write_text('ID=debian\nVERSION_ID="13"\n')
        (self.kit / "payload").mkdir(parents=True)
        payload = b"read-only plan fixture; extraction tested separately"
        self.digest = hashlib.sha256(payload).hexdigest()
        (self.kit / "payload/app.zip").write_bytes(payload)
        (self.kit / "payload/manifest.json").write_text(json.dumps({"version": "0.2.0", "file": "app.zip", "sha256": self.digest}))
        self.config_path = self.folder / "config.json"
        self.config_path.write_text(json.dumps(config(), ensure_ascii=False))
        self.runner = ReadOnlyRunner()
        self.state = lib.new_state(config(), self.digest)
        self.dns = mock.patch.object(lib, "resolve_domain", return_value={"93.184.216.34"})
        self.dns.start()
        self.accounts = mock.patch.object(deploy.pwd, "getpwnam", side_effect=KeyError("fixture account absent"))
        self.accounts.start()

    def tearDown(self):
        self.accounts.stop(); self.dns.stop(); self.temporary.cleanup()

    def call_main(self, argv, runner=None):
        output, error = io.StringIO(), io.StringIO()
        with mock.patch.object(deploy, "DeployPaths", return_value=self.paths), \
             mock.patch.object(deploy, "CommandRunner", return_value=runner or self.runner), \
             contextlib.redirect_stdout(output), contextlib.redirect_stderr(error), \
             mock.patch.object(deploy.subprocess, "run", side_effect=AssertionError("No real process may run")):
            result = deploy.main(argv)
        return result, output.getvalue(), error.getvalue()


class PlanTests(Fixture):
    def test_import_has_no_server_process_or_file_mutation(self):
        with mock.patch.object(subprocess, "run", side_effect=AssertionError("Import must not start a process")), \
             mock.patch.object(lib, "atomic_write", side_effect=AssertionError("Import must not write")):
            module = import_installer("syscohada_deployment_import_safety")
        self.assertTrue(callable(module.main))

    def test_plan_and_default_mode_only_run_read_only_checks(self):
        initial = sorted(str(p.relative_to(self.folder)) for p in self.folder.rglob("*"))
        for options in [["--plan"], []]:
            code, output, error = self.call_main(options + ["--config", str(self.config_path)])
            self.assertEqual(code, 0, error)
            result = json.loads(output)
            self.assertTrue(result["ready"])
            self.assertEqual(result["payload_sha256"], self.digest)
            self.assertNotIn("secrets", output)
        self.assertEqual(initial, sorted(str(p.relative_to(self.folder)) for p in self.folder.rglob("*")))
        self.assertFalse(self.paths.state_dir.exists())
        self.assertFalse(self.paths.base.exists())

    def test_wrong_dns_unsupported_os_and_non_tmpfs_block_readiness(self):
        with mock.patch.object(lib, "resolve_domain", return_value={"8.8.8.8"}):
            plan = deploy.build_plan(config(), self.paths, self.runner)
            self.assertFalse(plan["ready"])
        (self.system / "etc/os-release").write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
        plan = deploy.build_plan(config(), self.paths, ReadOnlyRunner(tmpfs=False))
        self.assertFalse(plan["ready"])
        self.assertGreaterEqual(len(plan["problems"]), 2)

    def test_expected_ip_must_belong_to_target_server(self):
        plan = deploy.build_plan(config(), self.paths, ReadOnlyRunner(addresses=["8.8.8.8"]))
        self.assertFalse(plan["ready"])

    def test_existing_control_panel_or_unmanaged_data_are_preserved_and_block_install(self):
        marker = self.paths.at("/home/clp/customer-data")
        marker.parent.mkdir(parents=True); marker.write_text("keep")
        plan = deploy.build_plan(config(), self.paths, self.runner)
        self.assertFalse(plan["ready"])
        self.assertEqual(marker.read_text(), "keep")
        marker.unlink(); marker.parent.rmdir()
        self.paths.base.mkdir(parents=True)
        self.assertFalse(deploy.build_plan(config(), self.paths, self.runner)["ready"])

    def test_payload_hash_mismatch_cannot_be_planned(self):
        (self.kit / "payload/app.zip").write_bytes(b"changed")
        with self.assertRaises(lib.DeploymentError):
            deploy.build_plan(config(), self.paths, self.runner)
        self.assertEqual(self.runner.commands, [])

    def test_malformed_manifest_is_an_operator_safe_error(self):
        for value in [[], {"version": "0.2.0", "file": "app.zip", "sha256": 7}]:
            (self.kit / "payload/manifest.json").write_text(json.dumps(value))
            with self.subTest(value=value), self.assertRaises(lib.DeploymentError):
                deploy.load_payload(self.paths)

    def test_resume_cannot_change_original_target_or_keys(self):
        lib.save_state(self.paths.state_file, self.state)
        before = self.paths.state_file.read_bytes()
        self.config_path.write_text(json.dumps(config(domain="other.example.com")))
        code, output, error = self.call_main(["--resume", "--config", str(self.config_path)])
        self.assertEqual(code, 2)
        self.assertIn("diffère", error)
        self.assertEqual(before, self.paths.state_file.read_bytes())

    def test_root_preflight_or_changed_target_preserves_existing_state_and_maintenance(self):
        self.paths.base.mkdir(parents=True)
        self.paths.maintenance.write_text("original maintenance condition")
        for stage, changed_target in [("ready", True), ("failed", False)]:
            self.state["stage"] = stage
            lib.save_state(self.paths.state_file, self.state)
            before = self.paths.state_file.read_bytes()
            self.config_path.write_text(json.dumps(config(domain="other.example.com") if changed_target else config()))
            with mock.patch.object(deploy.os, "geteuid", return_value=0), \
                 mock.patch.object(deploy, "load_state", return_value=copy.deepcopy(self.state)), \
                 mock.patch.object(deploy, "save_state") as save, \
                 mock.patch.object(deploy, "atomic_write") as write, \
                 mock.patch.object(deploy, "Installer") as installer, \
                 mock.patch.object(deploy, "build_plan", return_value={"ready": False, "problems": ["fixture DNS failure"]}):
                code, output, error = self.call_main(["--resume", "--config", str(self.config_path)])
                self.assertEqual(code, 2)
                save.assert_not_called(); write.assert_not_called(); installer.assert_not_called()
            self.assertEqual(before, self.paths.state_file.read_bytes())
            self.assertEqual(self.paths.maintenance.read_text(), "original maintenance condition")

    def test_state_appearing_under_lock_is_never_overwritten_by_second_install(self):
        concurrent = copy.deepcopy(self.state); concurrent["stage"] = "ready"
        published = {"value": False}
        expected = json.dumps(concurrent, sort_keys=True).encode()
        @contextlib.contextmanager
        def gate(path):
            self.paths.state_file.write_bytes(expected)
            self.paths.state_file.chmod(0o600)
            published["value"] = True
            yield
        def latest(path):
            return copy.deepcopy(concurrent) if published["value"] else None
        with mock.patch.object(deploy.os, "geteuid", return_value=0), \
             mock.patch.object(deploy, "load_state", side_effect=latest) as load, \
             mock.patch.object(deploy, "save_state") as save, \
             mock.patch.object(deploy, "exclusive_lock", side_effect=gate), \
             mock.patch.object(deploy, "show_status", return_value=0), \
             mock.patch.object(deploy, "Installer") as installer:
            code, output, error = self.call_main(["--install", "--config", str(self.config_path)])
        self.assertIn(code, (0, 2))
        load.assert_called_with(self.paths.state_file)
        save.assert_not_called(); installer.assert_not_called()
        self.assertEqual(self.paths.state_file.read_bytes(), expected)


class RuntimeTests(Fixture):
    def installer(self, runner=None):
        return deploy.Installer(config(), self.paths, runner or mock.Mock(), self.state)

    def test_process_runner_redacts_known_secrets_and_suppresses_sensitive_output(self):
        runner = deploy.CommandRunner(); runner.secrets = ["private-value"]
        failure = subprocess.CompletedProcess([], 1, "", "private-value DB_PASSWORD=other\n")
        with mock.patch.object(subprocess, "run", return_value=failure) as process:
            with self.assertRaises(lib.DeploymentError) as error:
                runner.run(["psql"], input_text="SQL private-value", sensitive=False, user="postgres")
            self.assertNotIn("private-value", str(error.exception))
            self.assertNotIn("other", str(error.exception))
            self.assertEqual(process.call_args.args[0], ["runuser", "-u", "postgres", "--", "psql"])
            self.assertNotIn("shell", process.call_args.kwargs)
            with self.assertRaises(lib.DeploymentError) as error:
                runner.run(["psql"], sensitive=True)
            self.assertNotIn("DB_PASSWORD", str(error.exception))

    def test_sql_secrets_are_input_and_never_process_arguments(self):
        runner = mock.Mock(); runner.run.return_value = subprocess.CompletedProcess([], 0, "1\n", "")
        installer = self.installer(runner)
        password = self.state["secrets"]["db_password"]
        sql = "ALTER ROLE fixture PASSWORD '"+password+"';"
        installer.psql(sql, "postgres", "postgres")
        arguments, options = runner.run.call_args
        self.assertNotIn(password, repr(arguments))
        self.assertEqual(options["input_text"], sql)
        self.assertTrue(options["sensitive"])

    def test_acme_without_explicit_acceptance_never_requests_certificate(self):
        runner = mock.Mock(); installer = self.installer(runner)
        installer.config = config(accept_acme_terms=False)
        with self.assertRaises(lib.DeploymentError): installer.certificate()
        runner.run.assert_not_called()

    def test_health_failure_restores_maintenance_flag(self):
        self.paths.base.mkdir(parents=True); self.paths.maintenance.write_text("pending")
        runner = mock.Mock()
        runner.run.side_effect = [subprocess.CompletedProcess([], 0, "", ""), lib.DeploymentError("HTTPS unavailable")]
        installer = self.installer(runner)
        with self.assertRaises(lib.DeploymentError): installer.health()
        self.assertTrue(self.paths.maintenance.is_file())
        self.assertNotEqual(self.state["stage"], "ready")

    def test_health_rejects_redirect_or_unrelated_login_even_when_curl_exits_zero(self):
        self.paths.base.mkdir(parents=True)
        for up, login in [("redirect\n301", "SYSCOHADA\n200"),
                          ("healthy\n200", "unrelated default website\n200"),
                          ("healthy\n200", "SYSCOHADA\n302")]:
            self.paths.maintenance.write_text("pending")
            runner = mock.Mock()
            runner.run.side_effect = [subprocess.CompletedProcess([], 0, "", ""),
                                      subprocess.CompletedProcess([], 0, up, ""),
                                      subprocess.CompletedProcess([], 0, login, "")]
            with self.subTest(up=up, login=login), self.assertRaises(lib.DeploymentError):
                self.installer(runner).health()
            self.assertTrue(self.paths.maintenance.exists())

    def test_health_accepts_exact_200_and_identified_application(self):
        self.paths.base.mkdir(parents=True); self.paths.maintenance.write_text("pending")
        runner = mock.Mock()
        runner.run.side_effect = [subprocess.CompletedProcess([], 0, "", ""),
                                  subprocess.CompletedProcess([], 0, "healthy\n200", ""),
                                  subprocess.CompletedProcess([], 0, "<title>SYSCOHADA CM</title>\n200", "")]
        self.installer(runner).health()
        self.assertFalse(self.paths.maintenance.exists())
        self.assertEqual(runner.run.call_count, 3)

    def test_failed_final_check_can_never_mark_installation_ready(self):
        installer = self.installer()
        self.paths.base.mkdir(parents=True); self.paths.maintenance.write_text("pending")
        names = ["packages", "users_and_paths", "application", "pki", "database", "environment",
                 "migrations_and_admin", "web_services", "certificate"]
        with contextlib.ExitStack() as stack:
            for name in names: stack.enter_context(mock.patch.object(installer, name))
            stack.enter_context(mock.patch.object(installer, "health", side_effect=lib.DeploymentError("fixture health failure")))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            with self.assertRaises(lib.DeploymentError): installer.install()
        self.assertNotEqual(self.state["stage"], "ready")
        self.assertNotEqual(lib.load_state(self.paths.state_file)["stage"], "ready")
        self.assertTrue(self.paths.maintenance.exists())

    def test_ready_is_written_only_after_all_simulated_checks_succeed(self):
        installer = self.installer()
        names = ["packages", "users_and_paths", "application", "pki", "database", "environment",
                 "migrations_and_admin", "web_services", "certificate"]
        def final_check():
            self.assertNotEqual(self.state["stage"], "ready")
            self.assertNotEqual(lib.load_state(self.paths.state_file)["stage"], "ready")
        with contextlib.ExitStack() as stack:
            for name in names: stack.enter_context(mock.patch.object(installer, name))
            health = stack.enter_context(mock.patch.object(installer, "health", side_effect=final_check))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            installer.install()
        health.assert_called_once()
        self.assertEqual(lib.load_state(self.paths.state_file)["stage"], "ready")
        self.assertEqual(lib.load_state(self.paths.state_file)["secrets"], self.state["secrets"])

    def test_status_returns_failure_when_https_is_down(self):
        self.state["stage"] = "ready"; lib.save_state(self.paths.state_file, self.state)
        runner = mock.Mock(); runner.run.return_value = subprocess.CompletedProcess([], 22, "", "unavailable")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(deploy.show_status(self.paths, runner), 2)
        self.assertEqual(json.loads(output.getvalue())["https_health"], "failed")

    def test_status_does_not_treat_redirect_as_ready(self):
        self.state["stage"] = "ready"; lib.save_state(self.paths.state_file, self.state)
        runner = mock.Mock(); runner.run.return_value = subprocess.CompletedProcess([], 0, "redirect\n301", "")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(deploy.show_status(self.paths, runner), 2)


if __name__ == "__main__":
    unittest.main()
