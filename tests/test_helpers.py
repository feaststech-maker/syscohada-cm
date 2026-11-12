"""Tests execute only temporary files and mocked DNS; no server mutation."""
import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import deploylib as lib


def config(**changes):
    value = {"domain": "dsf.example.com", "email": "admin@example.com", "company": "Société de test",
             "expected_ipv4": "93.184.216.34", "accept_acme_terms": True}
    value.update(changes)
    return value


def archive(path, additions=(), *, replace=None):
    root = lib.ROOT_FOLDER
    files = [(f"{root}/artisan", b"<?php echo 'fixture';"),
             (f"{root}/public/index.php", b"<?php // fixture"),
             (f"{root}/composer.lock", b"{}"),
             (f"{root}/vendor/autoload.php", b"<?php // fixture")]
    if replace:
        files = [(replace.get(name, name), content) for name, content in files]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as output:
            for name, content in files + list(additions):
                output.writestr(name, content)
    return lib.sha256_file(path)


class ConfigTests(unittest.TestCase):
    def test_normalises_domain_email_and_unicode_company(self):
        result = lib.validate_config(config(domain=" DSF.Example.COM. ", email="Admin@Example.COM", company=" Socie\u0301te\u0301 "))
        self.assertEqual(result["domain"], "dsf.example.com")
        self.assertEqual(result["email"], "admin@example.com")
        self.assertEqual(result["company"], "Société")

    def test_domain_injections_urls_and_ip_literals_are_rejected(self):
        for domain in ["https://example.com", "*.example.com", "a\nserver_name example.com", "a;example.com",
                       "localhost", "127.0.0.1", "a.local", "a.internal", "a..example.com", "-a.example.com",
                       "é.example.com", "a"*64+".example.com", "example.c", "bad_example.com", "example.com.."]:
            with self.subTest(domain=domain), self.assertRaises(lib.DeploymentError):
                lib.validate_config(config(domain=domain))

    def test_email_and_company_injections_are_rejected(self):
        for email in ["a@example.com\nX: y", "a@localhost", "bad", ".a@example.com", "a..b@example.com", "a.@example.com"]:
            with self.subTest(email=email), self.assertRaises(lib.DeploymentError):
                lib.validate_config(config(email=email))
        for company in ["", "A\0B", "A\nB", "A\n", "A\u202eB", "A"*201]:
            with self.subTest(company=repr(company)), self.assertRaises(lib.DeploymentError):
                lib.validate_config(config(company=company))
        self.assertEqual(len(lib.validate_config(config(company="É"*200))["company"]), 200)

    def test_required_unknown_and_wrong_type_fields_are_rejected(self):
        for value in [{}, {**config(), "api_token": "not-accepted"}, config(accept_acme_terms="yes"), config(company=123)]:
            with self.subTest(value=value), self.assertRaises(lib.DeploymentError):
                lib.validate_config(value)

    def test_nonpublic_expected_ipv4_is_rejected(self):
        for address in ["127.0.0.1", "10.0.0.1", "169.254.1.1", "224.0.0.1", "::1", "bad", "192.168.1.1"]:
            with self.subTest(address=address), self.assertRaises(lib.DeploymentError):
                lib.validate_config(config(expected_ipv4=address))

    def test_fingerprint_is_stable_but_changes_with_target(self):
        a = lib.config_fingerprint(config())
        b = lib.config_fingerprint(config(domain="DSF.EXAMPLE.COM."))
        self.assertEqual(a, b)
        self.assertNotEqual(a, lib.config_fingerprint(config(domain="other.example.com")))


class DnsTests(unittest.TestCase):
    def test_expected_ipv4_and_correct_local_ipv6_are_accepted(self):
        records = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 443, 0, 0)),
        ]
        with mock.patch.object(lib.socket, "getaddrinfo", return_value=records):
            result = lib.validate_dns(config(), ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"])
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["addresses"]), 2)

    def test_wrong_or_unaccounted_ipv6_blocks_deploy(self):
        with mock.patch.object(lib, "resolve_domain", return_value={"93.184.216.34", "2606:4700:4700::1111"}):
            with self.assertRaises(lib.DeploymentError):
                lib.validate_dns(config(), ["93.184.216.34"])
            with self.assertRaises(lib.DeploymentError):
                lib.validate_dns(config())

    def test_wrong_a_or_missing_expected_a_blocks_deploy(self):
        for records in [{"8.8.8.8"}, {"93.184.216.34", "8.8.8.8"}]:
            with mock.patch.object(lib, "resolve_domain", return_value=records), self.assertRaises(lib.DeploymentError):
                lib.validate_dns(config(), ["93.184.216.34"])

    def test_resolution_failure_has_operator_safe_error(self):
        with mock.patch.object(lib.socket, "getaddrinfo", side_effect=socket.gaierror("private diagnostic")):
            with self.assertRaises(lib.DeploymentError) as failure:
                lib.resolve_domain("dsf.example.com")
            self.assertNotIn("private diagnostic", str(failure.exception))


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.zip = self.directory / "app.zip"
        self.destination = self.directory / "releases"
    def tearDown(self):
        self.temporary.cleanup()
    def unpack(self, additions=()):
        digest = archive(self.zip, additions)
        return lib.safe_extract_app(self.zip, self.destination, digest)

    def test_valid_complete_archive_extracts_without_honouring_untrusted_modes(self):
        info = zipfile.ZipInfo(lib.ROOT_FOLDER + "/public/untrusted.php")
        info.create_system = 3
        info.external_attr = (stat.S_IFREG | 0o4777) << 16
        digest = archive(self.zip, [(info, b"fixture")])
        previous_umask = os.umask(0o077)
        try:
            root = lib.safe_extract_app(self.zip, self.destination, digest)
        finally:
            os.umask(previous_umask)
        self.assertTrue((root / "vendor/autoload.php").is_file())
        self.assertEqual(stat.S_IMODE((root / "public/untrusted.php").stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE((root / "public").stat().st_mode), 0o755)
        self.assertFalse(any(self.destination.glob(".syscohada-unpack-*")))

    def test_wrong_hash_fails_before_creating_output(self):
        archive(self.zip)
        with self.assertRaises(lib.DeploymentError):
            lib.safe_extract_app(self.zip, self.destination, "0"*64)
        self.assertFalse(self.destination.exists())

    def test_traversal_absolute_backslash_and_other_root_are_rejected(self):
        for name in ["../escape", "/absolute", "C:/escape", lib.ROOT_FOLDER+"/../escape", lib.ROOT_FOLDER+"/a\\b", "other/artisan"]:
            with self.subTest(name=name), self.assertRaises(lib.DeploymentError):
                self.unpack([(name, b"forbidden")])
            self.assertFalse((self.directory / "escape").exists())

    def test_symlink_and_special_files_are_rejected(self):
        for kind in [stat.S_IFLNK, stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFCHR]:
            info = zipfile.ZipInfo(lib.ROOT_FOLDER + "/public/file")
            info.create_system = 3; info.external_attr = (kind | 0o777) << 16
            with self.subTest(kind=kind), self.assertRaises(lib.DeploymentError):
                self.unpack([(info, b"/etc/passwd")])

    def test_nul_name_hidden_by_zipinfo_normalisation_is_rejected(self):
        archive(self.zip, [(lib.ROOT_FOLDER+"/public/evil!hidden.txt", b"fixture")])
        self.zip.write_bytes(self.zip.read_bytes().replace(b"evil!hidden.txt", b"evil\0hidden.txt"))
        with self.assertRaises(lib.DeploymentError):
            lib.safe_extract_app(self.zip, self.destination, lib.sha256_file(self.zip))
        self.assertFalse((self.destination/lib.ROOT_FOLDER).exists())

    def test_corrupted_deflate_stream_is_reported_and_never_published(self):
        archive(self.zip)
        with zipfile.ZipFile(self.zip) as package:
            entry = package.infolist()[0]
            offset = entry.header_offset + 30 + len(entry.filename.encode()) + len(entry.extra)
        content = bytearray(self.zip.read_bytes()); content[offset] = 0xff
        self.zip.write_bytes(content)
        with self.assertRaises(lib.DeploymentError) as failure:
            lib.safe_extract_app(self.zip, self.destination, lib.sha256_file(self.zip))
        self.assertEqual(str(failure.exception), "Le paquet ne peut pas être extrait en sécurité.")
        self.assertFalse((self.destination/lib.ROOT_FOLDER).exists())
        self.assertFalse(any(self.destination.glob(".syscohada-unpack-*")))

    def test_duplicate_and_file_directory_collision_are_rejected(self):
        for additions in [[(lib.ROOT_FOLDER+"/artisan", b"duplicate")],
                          [(lib.ROOT_FOLDER+"/artisan/child", b"collision")]]:
            with self.assertRaises(lib.DeploymentError):
                self.unpack(additions)

    def test_live_environment_database_and_private_storage_are_rejected(self):
        for name in [".env", ".env.production", "database/live.sqlite", "storage/app/private/balance.enc"]:
            with self.subTest(name=name), self.assertRaises(lib.DeploymentError):
                self.unpack([(lib.ROOT_FOLDER+"/"+name, b"private")])
        root = self.unpack([(lib.ROOT_FOLDER+"/.env.example", b"APP_KEY=\n")])
        self.assertTrue((root/".env.example").exists())

    def test_existing_target_is_never_overwritten(self):
        existing = self.destination / lib.ROOT_FOLDER
        existing.mkdir(parents=True)
        marker = existing / "customer-data"
        marker.write_text("keep")
        digest = archive(self.zip)
        with self.assertRaises(lib.DeploymentError):
            lib.safe_extract_app(self.zip, self.destination, digest)
        self.assertEqual(marker.read_text(), "keep")

    def test_symlink_in_destination_parent_is_rejected(self):
        outside = self.directory / "outside"; outside.mkdir()
        linked = self.directory / "linked"; linked.symlink_to(outside, target_is_directory=True)
        digest = archive(self.zip)
        with self.assertRaises(lib.DeploymentError):
            lib.safe_extract_app(self.zip, linked / "releases", digest)
        self.assertEqual(list(outside.iterdir()), [])

    def test_expansion_and_per_file_limits_are_enforced(self):
        with mock.patch.object(lib, "MAX_ENTRY_BYTES", 100), self.assertRaises(lib.DeploymentError):
            self.unpack([(lib.ROOT_FOLDER+"/large.txt", os.urandom(101))])
        with self.assertRaises(lib.DeploymentError):
            self.unpack([(lib.ROOT_FOLDER+"/bomb.txt", b"0"*400_000)])
        with mock.patch.object(lib, "MAX_ENTRIES", 3), self.assertRaises(lib.DeploymentError):
            self.unpack()

    def test_incomplete_archive_is_not_published(self):
        digest = archive(self.zip, replace={lib.ROOT_FOLDER+"/artisan": lib.ROOT_FOLDER+"/not-artisan"})
        with self.assertRaises(lib.DeploymentError):
            lib.safe_extract_app(self.zip, self.destination, digest)
        self.assertFalse((self.destination/lib.ROOT_FOLDER).exists())


class StateAndFileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.path = self.directory / "state.json"
    def tearDown(self):
        self.temporary.cleanup()

    def test_state_roundtrip_preserves_keys_during_resume_and_remains_private(self):
        value = lib.new_state(config(), "a"*64)
        self.assertEqual(len(base64.b64decode(value["secrets"]["app_key"][7:])),32)
        lib.save_state(self.path, value)
        loaded = lib.load_state(self.path)
        loaded["stage"] = "database"
        lib.save_state(self.path, loaded)
        self.assertEqual(lib.load_state(self.path)["secrets"], value["secrets"])
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode),0o600)

    def test_resume_refuses_secret_or_target_rotation(self):
        value = lib.new_state(config(), "a"*64);lib.save_state(self.path,value)
        changed = copy.deepcopy(value);changed["secrets"]["db_password"]="b"*64
        with self.assertRaises(lib.DeploymentError): lib.save_state(self.path,changed)
        changed = lib.new_state(config(domain="other.example.com"),"a"*64)
        with self.assertRaises(lib.DeploymentError): lib.save_state(self.path,changed)
        self.assertEqual(lib.load_state(self.path),value)

    def test_permissive_state_and_symlink_are_rejected(self):
        lib.save_state(self.path,lib.new_state(config(),"a"*64));self.path.chmod(0o644)
        with self.assertRaises(lib.DeploymentError):lib.load_state(self.path)
        other=self.directory/"other";other.write_text("keep")
        linked=self.directory/"linked";linked.symlink_to(other)
        with self.assertRaises(lib.DeploymentError):lib.atomic_write(linked,"replace")
        self.assertEqual(other.read_text(),"keep")
        with self.assertRaises(lib.DeploymentError):lib.load_state(linked)

    def test_immutable_state_detects_fingerprint_tampering(self):
        value=lib.new_state(config(),"a"*64);value["config"]["domain"]="other.example.com"
        with self.assertRaises(lib.DeploymentError):lib.save_state(self.path,value)

    def test_malformed_state_fields_have_operator_safe_errors(self):
        for key, value in [("payload_sha256", 7), ("stage", None), ("stage", "ready\nforged"),
                           ("created_at", "yesterday"), ("created_at", "2026-11-11T10:00:00"),
                           ("created_at", 123), ("secrets", None)]:
            state = lib.new_state(config(), "a"*64); state[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(lib.DeploymentError):
                lib.save_state(self.path, state)
        self.assertFalse(self.path.exists())

    def test_exclusive_lock_prevents_parallel_installers(self):
        path=self.directory/"install.lock"
        with lib.exclusive_lock(path):
            with self.assertRaises(lib.DeploymentError):
                with lib.exclusive_lock(path):pass
        with lib.exclusive_lock(path):pass

    def test_redaction_masks_known_values_and_environment_diagnostics(self):
        text="private-secret DB_PASSWORD=not-yet-known\nAPP_KEY=base64:other\nstatus=ready"
        result=lib.redact(text,["private-secret"])
        self.assertNotIn("private-secret",result)
        self.assertNotIn("not-yet-known",result)
        self.assertNotIn("base64:other",result)
        self.assertIn("status=ready",result)

    def test_template_has_no_eval_and_rejects_control_injection(self):
        result=lib.render_template("server_name $DOMAIN; $$literal",{"DOMAIN":"dsf.example.com"})
        self.assertEqual(result,"server_name dsf.example.com; $literal")
        with self.assertRaises(lib.DeploymentError):lib.render_template("$DOMAIN",{"DOMAIN":"a\nroot /;"})
        with self.assertRaises(lib.DeploymentError):lib.render_template("$MISSING",{})


if __name__ == "__main__":
    unittest.main()
