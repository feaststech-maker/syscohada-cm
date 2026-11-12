#!/usr/bin/env python3
"""SYSCOHADA CM: bounded first-install deployment on a dedicated Debian 13 VPS.

No action runs at import. All process calls use argv arrays; SQL secrets use stdin.
The installer never reinstalls an OS, edits SSH/firewalls, or drops an application DB.
"""
from __future__ import annotations

import argparse
import base64
import dataclasses
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from deploylib import (DeploymentError, atomic_write, config_fingerprint, exclusive_lock,
                       load_state, new_state, redact, render_template, safe_extract_app,
                       save_state, sha256_file, validate_config, validate_dns)

VERSION = "0.2.0"
WEB_USER = "syscohada_web"
MIGRATE_USER = "syscohada_migrate"
DB_USER = "syscohada_api"
DB_NAME = "syscohada"
PG_PORT = "5433"


@dataclasses.dataclass(frozen=True)
class DeployPaths:
    kit: Path = dataclasses.field(default_factory=lambda: Path(__file__).resolve().parents[1])
    system: Path = Path("/")

    def at(self, absolute: str) -> Path:
        return self.system / absolute.lstrip("/")

    @property
    def base(self) -> Path: return self.at("/opt/syscohada")
    @property
    def release(self) -> Path: return self.base / "releases" / VERSION
    @property
    def current(self) -> Path: return self.base / "current"
    @property
    def state_dir(self) -> Path: return self.at("/var/lib/syscohada-deploy")
    @property
    def state_file(self) -> Path: return self.state_dir / "state.json"
    @property
    def nginx_site(self) -> Path: return self.at("/etc/nginx/sites-available/syscohada.conf")
    @property
    def maintenance(self) -> Path: return self.base / "maintenance.flag"


class CommandRunner:
    """A replaceable runner for tests. Never prints process argv or sensitive input."""
    def __init__(self) -> None:
        self.secrets: list[str] = []

    def run(self, argv: list[str], *, input_text: str | None = None, cwd: Path | None = None,
            user: str | None = None, env: dict[str, str] | None = None,
            sensitive: bool = False, allow_failure: bool = False, label: str = "commande") -> subprocess.CompletedProcess:
        command = (["runuser", "-u", user, "--"] if user else []) + [str(x) for x in argv]
        process_env = os.environ.copy()
        process_env.update(env or {})
        if user in {WEB_USER, MIGRATE_USER}:
            process_env["PGSSLROOTCERT"] = "/etc/syscohada/pg-ca.crt"
        try:
            result = subprocess.run(command, input=input_text, cwd=cwd, env=process_env,
                                    text=True, capture_output=True, check=False, umask=0o007 if user else -1)
        except OSError:
            if allow_failure: return subprocess.CompletedProcess(command, 127, "", "")
            raise DeploymentError(f"{label}: exécutable indisponible.") from None
        if result.returncode and not allow_failure:
            detail = ""
            if not sensitive:
                cleaned = redact(result.stderr[-1200:], self.secrets)
                cleaned = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", cleaned)
                detail = f" {cleaned.strip()}" if cleaned.strip() else ""
            raise DeploymentError(f"{label}: échec (code {result.returncode}).{detail}")
        return result


def read_os_release(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        for line in path.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                result[key] = value.strip().strip('"')
    except OSError:
        pass
    return result


def local_addresses(runner: CommandRunner) -> set[str]:
    result = runner.run(["ip", "-j", "address", "show", "scope", "global"], allow_failure=True, label="adresses locales")
    if result.returncode: return set()
    try:
        return {a["local"] for interface in json.loads(result.stdout)
                for a in interface.get("addr_info", []) if "local" in a}
    except (ValueError, TypeError, KeyError):
        return set()


def load_payload(paths: DeployPaths) -> dict[str, str]:
    try:
        data = json.loads((paths.kit / "payload/manifest.json").read_text())
    except (OSError, ValueError):
        raise DeploymentError("Manifeste de l’application absent ou illisible.") from None
    if not isinstance(data, dict) or data.get("version") != VERSION or data.get("file") != "app.zip" or not isinstance(data.get("sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", data["sha256"]):
        raise DeploymentError("Manifeste de l’application non reconnu.")
    archive = paths.kit / "payload/app.zip"
    if not archive.is_file() or archive.is_symlink() or sha256_file(archive) != data["sha256"]:
        raise DeploymentError("Empreinte du paquet Laravel incorrecte.")
    return data


def existing_conflicts(paths: DeployPaths, config: dict[str, Any], managed: bool) -> list[str]:
    problems: list[str] = []
    for folder in ["/home/clp", "/etc/cloudpanel", "/usr/local/cpanel", "/usr/local/CyberCP", "/usr/local/hestia", "/etc/webmin", "/etc/psa"]:
        if paths.at(folder).exists(): problems.append("Panneau de contrôle existant : installation dédiée requise."); break
    protected = [paths.base, paths.at("/etc/syscohada"), paths.state_dir,
                 paths.nginx_site, paths.at("/etc/php/8.4/fpm/pool.d/syscohada.conf"),
                 paths.at("/etc/postgresql/17/syscohada")]
    if not managed and any(p.exists() or p.is_symlink() for p in protected):
        problems.append("Un emplacement SYSCOHADA existe sans état de déploiement reconnu.")
    sites = paths.at("/etc/nginx/sites-enabled")
    if sites.exists():
        for site in sites.iterdir():
            if site.name not in {"default", "syscohada.conf"}:
                problems.append("Nginx héberge déjà un site : ce programme vise un VPS dédié."); break
    confd = paths.at("/etc/nginx/conf.d")
    if confd.exists() and any(confd.glob("*.conf")):
        problems.append("Configuration Nginx additionnelle détectée : revue manuelle nécessaire.")
    if not managed:
        pgdata = paths.at("/var/lib/postgresql")
        if pgdata.exists() and any(pgdata.rglob("PG_VERSION")):
            problems.append("Une instance PostgreSQL existe déjà ; elle ne sera pas modifiée.")
        if paths.at(f"/etc/letsencrypt/live/{config['domain']}").exists():
            problems.append("Un certificat existe déjà pour ce domaine hors de cette installation.")
        for name in [WEB_USER, MIGRATE_USER]:
            try: pwd.getpwnam(name)
            except KeyError: continue
            problems.append("Un compte système réservé existe déjà sans état reconnu.")
    return problems


def build_plan(config: dict[str, Any], paths: DeployPaths, runner: CommandRunner,
               state: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = load_payload(paths)
    os_info = read_os_release(paths.at("/etc/os-release"))
    problems = []
    if os_info.get("ID") != "debian" or os_info.get("VERSION_ID") != "13":
        problems.append("Système non supporté : un VPS dédié Debian 13 est requis.")
    managed = state is not None
    problems.extend(existing_conflicts(paths, config, managed))
    addresses = local_addresses(runner)
    if config["expected_ipv4"] not in addresses:
        problems.append("L’IPv4 annoncée ne figure pas sur les interfaces de ce VPS.")
    try:
        dns = validate_dns(config, local_addresses=addresses)
    except DeploymentError as exc:
        dns = {"ready": False, "message": str(exc)}
        problems.append(str(exc))
    # Read-only check. /run is required to be memory-backed for financial temporaries.
    fs = runner.run(["findmnt", "-n", "-o", "FSTYPE", "--target", "/run"], allow_failure=True, label="montage temporaire")
    if fs.returncode or fs.stdout.strip() != "tmpfs":
        problems.append("/run doit être un montage tmpfs pour les fichiers temporaires financiers.")
    listeners = runner.run(["ss", "-H", "-ltn"], allow_failure=True, label="ports locaux")
    if listeners.returncode:
        problems.append("Inventaire des ports indisponible : installer iproute2 avant le précontrôle.")
    if not managed:
        for port in ["80", "443", PG_PORT]:
            if re.search(r"(?:\]|[0-9.*]):"+port+r"\s", listeners.stdout):
                problems.append("Le port réservé "+port+" est déjà utilisé ; un VPS vierge est requis.")
    return {"ready": not problems, "version": VERSION, "domain": config["domain"],
            "expected_ipv4": config["expected_ipv4"], "dns": dns, "problems": problems,
            "ports": {"public_tcp": [80,443], "postgresql_loopback_tcp": [5433]},
            "changes": ["Paquets signés Debian : PHP 8.4-FPM, PostgreSQL 17, Nginx, Certbot",
                        "Cluster PostgreSQL dédié 17/syscohada sur localhost:5433",
                        "Deux comptes séparés : maintenance et processus web",
                        "Vhost HTTPS dédié et certificat public, après acceptation ACME",
                        "Migration Laravel, administrateur initial, contrôles de santé"],
            "paths": {"application": str(paths.release), "state": str(paths.state_file)},
            "untouched": ["OS existant", "configuration SSH", "pare-feu", "autres bases et sites"],
            "payload_sha256": payload["sha256"]}


class Installer:
    PACKAGES = ["nginx", "postgresql-17", "postgresql-client-17", "php8.4-cli", "php8.4-fpm",
                "php8.4-pgsql", "php8.4-xml", "php8.4-mbstring", "php8.4-zip", "php8.4-gd",
                "php8.4-bcmath", "php8.4-curl", "php8.4-intl", "php8.4-opcache", "composer",
                "openssl", "curl", "ca-certificates", "unzip", "certbot", "python3-certbot-nginx"]

    def __init__(self, config: dict[str, Any], paths: DeployPaths, runner: CommandRunner, state: dict[str, Any]):
        self.config, self.paths, self.runner, self.state = config, paths, runner, state
        secret_values = state.get("secrets", {}).values()
        self.runner.secrets = [str(v) for v in secret_values]

    def step(self, name: str, work: Any) -> None:
        print(f"→ {name}", flush=True)
        work()
        self.state["stage"] = name
        self.state["updated_at"] = int(time.time())
        save_state(self.paths.state_file, self.state)

    def template(self, name: str, values: dict[str, str]) -> str:
        return render_template((self.paths.kit / "templates" / name).read_text(), values)

    @staticmethod
    def safe_directory(path: Path) -> None:
        for ancestor in (path, *path.parents):
            if ancestor.is_symlink() or (ancestor.exists() and not ancestor.is_dir()):
                raise DeploymentError("Un répertoire géré ou son parent est un lien ou un fichier.")
        path.mkdir(parents=True, exist_ok=True)

    def write(self, path: Path, value: str, mode: int = 0o644, owner: str | None = None, group: str | None = None) -> None:
        self.safe_directory(path.parent)
        if path.is_symlink(): raise DeploymentError("Un fichier de configuration réservé est un lien symbolique.")
        atomic_write(path, value, mode=mode)
        if owner or group: os.chown(path, pwd.getpwnam(owner or "root").pw_uid, grp.getgrnam(group or owner or "root").gr_gid)

    def packages(self) -> None:
        self.runner.run(["apt-get", "update"], label="actualisation des paquets Debian")
        self.runner.run(["apt-get", "install", "-y", "--no-install-recommends", *self.PACKAGES], env={"DEBIAN_FRONTEND": "noninteractive"}, label="installation des paquets Debian")
        self.runner.run(["php8.4", "-r", "exit(version_compare(PHP_VERSION,'8.4.27','>=') ? 0 : 1);"], label="version corrigée de PHP")

    def users_and_paths(self) -> None:
        for name in [WEB_USER, MIGRATE_USER]:
            try: pwd.getpwnam(name)
            except KeyError:
                self.runner.run(["useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/opt/syscohada", "--shell", "/usr/sbin/nologin", name], label="compte système dédié")
        # Maintenance can read runtime configuration, but the web account cannot read migration.env.
        self.runner.run(["usermod", "-a", "-G", WEB_USER, MIGRATE_USER], label="lecture de configuration par la maintenance")
        for path, owner, group, mode in [
            (self.paths.base, "root", "root", 0o755),
            (self.paths.base / "releases", "root", "root", 0o755),
            (self.paths.base / "tools", "root", "root", 0o755),
            (self.paths.at("/etc/syscohada"), "root", WEB_USER, 0o750),
            (self.paths.at("/run/syscohada-php"), WEB_USER, WEB_USER, 0o700),
            (self.paths.at("/run/syscohada-cli"), MIGRATE_USER, MIGRATE_USER, 0o700),
            (self.paths.at("/run/syscohada-nginx"), "www-data", "www-data", 0o700),
            (self.paths.at("/var/lib/syscohada-acme"), "root", "root", 0o755),
        ]:
            self.safe_directory(path)
            os.chown(path, pwd.getpwnam(owner).pw_uid, grp.getgrnam(group).gr_gid); path.chmod(mode)
        for helper in ["provision.php", "check-runtime.php"]:
            source = self.paths.kit / "bin" / helper
            if not source.is_file() or source.is_symlink(): raise DeploymentError("Outil de provisionnement absent.")
            self.write(self.paths.base / "tools" / helper, source.read_text(), 0o644)
        self.write(self.paths.at("/etc/tmpfiles.d/syscohada.conf"), self.template("tmpfiles.conf.tpl", {}), 0o644)
        self.write(self.paths.maintenance, "Déploiement non validé.\n", 0o644)

    def application(self) -> None:
        if not self.paths.release.exists():
            # A crash before publication leaves only a private, uniquely named staging folder.
            # A resumed run can extract afresh without replacing any existing release.
            with tempfile.TemporaryDirectory(prefix=".unpack-", dir=self.paths.base / "releases") as temporary:
                root = safe_extract_app(self.paths.kit / "payload/app.zip", Path(temporary), self.state["payload_sha256"])
                if self.paths.release.exists(): raise DeploymentError("Répertoire de release concurrent.")
                root.rename(self.paths.release)
        if not (self.paths.release / "artisan").is_file() or not (self.paths.release / "vendor/autoload.php").is_file():
            raise DeploymentError("Release Laravel incomplète.")
        uid, gid = pwd.getpwnam(MIGRATE_USER).pw_uid, grp.getgrnam(WEB_USER).gr_gid
        for base, directories, files in os.walk(self.paths.release, followlinks=False):
            directory = Path(base)
            if directory.is_symlink() or any((directory / name).is_symlink() for name in directories):
                raise DeploymentError("Lien symbolique non autorisé dans la release.")
            os.chown(directory, uid, gid); directory.chmod(0o750)
            for name in files:
                path = directory / name
                if path.is_symlink():
                    if path.name not in {".env", ".env.migration"}: raise DeploymentError("Lien non reconnu dans la release.")
                    continue
                os.chown(path, uid, gid); path.chmod(0o640)
        self.paths.release.chmod(0o751)  # Nginx may traverse to public/, but cannot read private application files.
        public = self.paths.release / "public"
        for base, dirs, files in os.walk(public):
            Path(base).chmod(0o755)
            for name in files: (Path(base) / name).chmod(0o644)
        for name in ["storage", "storage/app/private", "storage/framework/cache/data", "storage/framework/sessions", "storage/framework/views", "storage/logs", "bootstrap/cache"]:
            path = self.paths.release / name
            self.safe_directory(path)
            # Only storage is web-writable. bootstrap/cache is generated by maintenance, then web-readable.
            owner = WEB_USER if name.startswith("storage") else MIGRATE_USER
            os.chown(path, pwd.getpwnam(owner).pw_uid, gid); path.chmod(0o770 if name.startswith("storage") else 0o750)
        self.storage_permissions()
        current = self.paths.current
        if current.exists() and not current.is_symlink(): raise DeploymentError("Le chemin current n’est pas un lien géré.")
        if current.is_symlink() and current.resolve() != self.paths.release.resolve(): raise DeploymentError("Une autre release est active ; mise à jour manuelle requise.")
        if not current.exists(): current.symlink_to(self.paths.release)

    def storage_permissions(self) -> None:
        # CLI and FPM share private runtime data; compiled code/config stays outside this tree.
        uid, gid = pwd.getpwnam(WEB_USER).pw_uid, grp.getgrnam(WEB_USER).gr_gid
        for base, directories, files in os.walk(self.paths.release / "storage", followlinks=False):
            directory = Path(base)
            if directory.is_symlink() or any((directory / name).is_symlink() for name in directories):
                raise DeploymentError("Lien interdit dans le stockage privé.")
            os.chown(directory, uid, gid); directory.chmod(0o2770)
            for name in files:
                path = directory / name
                if path.is_symlink(): raise DeploymentError("Lien interdit dans le stockage privé.")
                os.chown(path, uid, gid); path.chmod(0o660)

    def pki(self) -> None:
        pki = self.paths.state_dir / "pki"; self.safe_directory(pki); pki.chmod(0o700)
        ca_key, ca_cert = pki / "ca.key", pki / "ca.crt"
        if ca_key.exists() != ca_cert.exists(): raise DeploymentError("Autorité TLS incomplète ; aucune clé ne sera régénérée automatiquement.")
        if not ca_key.exists():
            self.runner.run(["openssl", "req", "-x509", "-newkey", "rsa:4096", "-sha256", "-nodes", "-days", "3650", "-keyout", str(ca_key), "-out", str(ca_cert), "-subj", "/CN=SYSCOHADA Internal PostgreSQL CA", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"], sensitive=True, label="création de l’autorité TLS interne")
        ca_key.chmod(0o600); ca_cert.chmod(0o644)
        server_key, server_cert, csr = pki / "server.key", pki / "server.crt", pki / "server.csr"
        if server_key.exists() != server_cert.exists(): raise DeploymentError("Certificat PostgreSQL incomplet ; intervention requise.")
        if not server_key.exists():
            self.runner.run(["openssl", "req", "-new", "-newkey", "rsa:3072", "-nodes", "-keyout", str(server_key), "-out", str(csr), "-subj", "/CN=localhost"], sensitive=True, label="clé TLS PostgreSQL")
            extensions = pki / "server.ext"
            atomic_write(extensions, "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n", mode=0o600)
            self.runner.run(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(server_cert), "-days", "3650", "-sha256", "-extfile", str(extensions)], sensitive=True, label="signature TLS PostgreSQL")
        server_key.chmod(0o600)
        self.write(self.paths.at("/etc/syscohada/pg-ca.crt"), ca_cert.read_text(), 0o640, "root", WEB_USER)

    def database(self) -> None:
        cluster = self.paths.at("/etc/postgresql/17/syscohada")
        if not cluster.exists():
            self.runner.run(["pg_createcluster", "17", "syscohada", "--port", PG_PORT, "--start-conf=auto", "--locale", "C.UTF-8", "--encoding", "UTF8"], label="cluster PostgreSQL dédié")
        tls = cluster / "tls"; self.safe_directory(tls)
        os.chown(tls, pwd.getpwnam("postgres").pw_uid, grp.getgrnam("postgres").gr_gid); tls.chmod(0o700)
        for name, mode in [("server.key",0o600),("server.crt",0o644)]:
            self.write(tls / name, (self.paths.state_dir / "pki" / name).read_text(), mode, "postgres", "postgres")
        self.write(cluster / "conf.d/syscohada.conf", self.template("postgresql.conf.tpl", {"PG_TLS_DIR": str(tls), "PG_PORT": PG_PORT}), 0o640, "postgres", "postgres")
        self.write(cluster / "pg_hba.conf", self.template("pg_hba.conf.tpl", {}), 0o640, "postgres", "postgres")
        self.runner.run(["systemctl", "enable", "--now", "postgresql@17-syscohada"], label="démarrage du cluster dédié")
        self.runner.run(["pg_ctlcluster", "17", "syscohada", "restart"], label="TLS du cluster dédié")
        self.runner.run(["pg_isready", "-h", "/var/run/postgresql", "-p", PG_PORT], label="disponibilité PostgreSQL")
        password = self.state["secrets"]["db_password"]
        if not re.fullmatch(r"[A-Za-z0-9_-]{24,128}", password): raise DeploymentError("Secret DB interne invalide.")
        sql = self.template("roles.sql.tpl", {"DB_PASSWORD": password})
        self.psql(sql, "postgres", "postgres")
        exists = self.psql("SELECT 1 FROM pg_database WHERE datname='syscohada';\n", "postgres", "postgres", capture=True)
        if exists.strip() != "1":
            self.runner.run(["createdb", "-h", "/var/run/postgresql", "-p", PG_PORT, "-O", MIGRATE_USER, DB_NAME], user="postgres", label="base dédiée")

    def psql(self, sql: str, user: str, database: str, capture: bool = False) -> str:
        result = self.runner.run(["psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-h", "/var/run/postgresql", "-p", PG_PORT, "-d", database], user=user, input_text=sql, sensitive=True, label="configuration SQL privée")
        return result.stdout if capture else ""

    def environment(self) -> None:
        common = {"DOMAIN": self.config["domain"], "APP_KEY": self.state["secrets"]["app_key"], "PG_PORT": PG_PORT,
                  "DB_PASSWORD": self.state["secrets"]["db_password"]}
        self.write(self.paths.at("/etc/syscohada/runtime.env"), self.template("runtime.env.tpl", common), 0o640, "root", WEB_USER)
        self.write(self.paths.at("/etc/syscohada/migration.env"), self.template("migration.env.tpl", common), 0o640, "root", MIGRATE_USER)
        for name, target in [(".env", self.paths.at("/etc/syscohada/runtime.env")), (".env.migration", self.paths.at("/etc/syscohada/migration.env"))]:
            link = self.paths.release / name
            if link.is_symlink() and link.resolve() == target.resolve(): continue
            if link.exists() or link.is_symlink(): raise DeploymentError("Un fichier d’environnement non géré existe.")
            link.symlink_to(target)
        cache = self.paths.release / "bootstrap/cache/config.php"
        if cache.exists(): cache.unlink()  # Never let a cached runtime connection override migration.env.
        cli_env = {"TMPDIR":"/run/syscohada-cli", "COMPOSER_HOME":"/run/syscohada-cli/composer", "COMPOSER_ALLOW_SUPERUSER":"0"}
        self.runner.run(["composer", "dump-autoload", "--no-dev", "--classmap-authoritative", "--no-scripts", "--no-interaction"], cwd=self.paths.release, user=MIGRATE_USER, env=cli_env, sensitive=True, label="autoloader de production")
        self.runner.run(["composer", "check-platform-reqs", "--no-dev"], cwd=self.paths.release, user=MIGRATE_USER, env=cli_env, label="extensions PHP")
        self.runner.run(["php8.4", "artisan", "package:discover", "--no-interaction"], cwd=self.paths.release, user=MIGRATE_USER, env=cli_env, sensitive=True, label="découverte Laravel")

    def migrations_and_admin(self) -> None:
        env = {"TMPDIR":"/run/syscohada-cli", "APP_CONFIG_CACHE":"/run/syscohada-cli/migration-config-disabled.php"}
        cache_disabled = self.paths.at("/run/syscohada-cli/migration-config-disabled.php")
        if cache_disabled.exists(): raise DeploymentError("Cache de migration inattendu.")
        self.runner.run(["php8.4", "artisan", "--env=migration", "migrate", "--force", "--no-interaction"], cwd=self.paths.release, user=MIGRATE_USER, env=env, sensitive=True, label="migrations Laravel")
        self.psql(self.template("runtime-grants.sql.tpl", {}), MIGRATE_USER, DB_NAME)
        secret = self.paths.at("/run/syscohada-cli/bootstrap-secret")
        self.write(secret, self.state["secrets"]["admin_password"]+"\n", 0o600, MIGRATE_USER, MIGRATE_USER)
        try:
            self.runner.run(["php8.4", str(self.paths.base / "tools/provision.php"), "--app", str(self.paths.release), "--secret-file", str(secret), "--tenant", self.state["tenant_id"], "--actor", self.state["actor_id"], "--email", self.config["email"], "--company", self.config["company"]], user=MIGRATE_USER, cwd=self.paths.release, env=env, sensitive=True, label="administrateur initial")
        finally:
            if secret.exists(): secret.unlink()
        credentials = f"SYSCOHADA CM — installation privée\nURL: https://{self.config['domain']}/login\nEmail: {self.config['email']}\nMot de passe initial: {self.state['secrets']['admin_password']}\nTenant: {self.state['tenant_id']}\nConserver ce fichier hors du webroot et dans un coffre sécurisé.\n"
        self.write(self.paths.at("/root/syscohada-identifiants.txt"), credentials, 0o600)
        # Runtime-only cache; migration credentials are never compiled into this cache.
        self.runner.run(["php8.4", "artisan", "optimize", "--no-interaction"], cwd=self.paths.release, user=MIGRATE_USER, env={"TMPDIR":"/run/syscohada-cli"}, sensitive=True, label="cache Laravel runtime")
        self.storage_permissions()
        for file in (self.paths.release / "bootstrap/cache").glob("*.php"):
            os.chown(file, pwd.getpwnam(MIGRATE_USER).pw_uid, grp.getgrnam(WEB_USER).gr_gid); file.chmod(0o640)

    def web_services(self) -> None:
        self.write(self.paths.at("/etc/php/8.4/fpm/pool.d/syscohada.conf"), self.template("fpm-pool.conf.tpl", {}), 0o644)
        certificate_exists = self.paths.at("/etc/letsencrypt/live/"+self.config["domain"]+"/fullchain.pem").is_file()
        template = "nginx-https.conf.tpl" if certificate_exists else "nginx-http.conf.tpl"
        self.write(self.paths.nginx_site, self.template(template, {"DOMAIN":self.config["domain"]}), 0o644)
        enabled = self.paths.at("/etc/nginx/sites-enabled/syscohada.conf")
        if enabled.is_symlink() and enabled.resolve() == self.paths.nginx_site.resolve(): pass
        elif enabled.exists() or enabled.is_symlink(): raise DeploymentError("Vhost activé non reconnu.")
        else: enabled.symlink_to(self.paths.nginx_site)
        self.runner.run(["php-fpm8.4", "-t"], label="configuration PHP-FPM")
        self.runner.run(["nginx", "-t"], label="configuration Nginx")
        self.runner.run(["systemctl", "enable", "--now", "php8.4-fpm", "nginx"], label="services web")
        self.runner.run(["systemctl", "reload", "php8.4-fpm", "nginx"], label="rechargement web")

    def certificate(self) -> None:
        if not self.config["accept_acme_terms"]: raise DeploymentError("L’accord ACME explicite est requis avant émission du certificat.")
        self.runner.run(["certbot", "certonly", "--webroot", "--webroot-path", "/var/lib/syscohada-acme", "--domain", self.config["domain"], "--email", self.config["email"], "--agree-tos", "--non-interactive", "--keep-until-expiring"], sensitive=True, label="certificat HTTPS public")
        self.write(self.paths.nginx_site, self.template("nginx-https.conf.tpl", {"DOMAIN":self.config["domain"]}), 0o644)
        hook = self.paths.at("/etc/letsencrypt/renewal-hooks/deploy/syscohada-reload.sh")
        self.write(hook, self.template("certbot-hook.sh.tpl", {"DOMAIN":self.config["domain"]}), 0o755)
        self.runner.run(["nginx", "-t"], label="configuration HTTPS")
        self.runner.run(["systemctl", "reload", "nginx"], label="activation HTTPS")
        self.runner.run(["systemctl", "enable", "--now", "certbot.timer"], label="renouvellement HTTPS")

    def health(self) -> None:
        self.runner.run(["php8.4", str(self.paths.base / "tools/check-runtime.php"), "--app", str(self.paths.release), "--actor", self.state["actor_id"], "--tenant", self.state["tenant_id"]], cwd=self.paths.release, user=WEB_USER, env={"TMPDIR":"/run/syscohada-php"}, sensitive=True, label="isolation et interface Laravel")
        self.paths.maintenance.unlink(missing_ok=True)
        try:
            for route in ["/up", "/login"]:
                result=self.runner.run(["curl", "--fail", "--silent", "--show-error", "--max-time", "20", "--write-out", "\n%{http_code}", "https://"+self.config["domain"]+route], sensitive=True, label="santé HTTPS")
                parts=result.stdout.rsplit("\n",1)
                if len(parts)!=2 or parts[1].strip()!="200" or (route=="/login" and "syscohada" not in parts[0].lower()):
                    raise DeploymentError("Le vhost HTTPS ne renvoie pas la page SYSCOHADA attendue (HTTP 200).")
        except Exception:
            self.write(self.paths.maintenance, "Contrôle de santé non validé.\n", 0o644)
            raise

    def install(self) -> None:
        for name, action in [("paquets",self.packages),("comptes et répertoires",self.users_and_paths),
                             ("application",self.application),("certificats internes",self.pki),
                             ("PostgreSQL dédié",self.database),("configuration Laravel",self.environment),
                             ("migrations et administrateur",self.migrations_and_admin),("services web",self.web_services),
                             ("HTTPS",self.certificate),("contrôles finaux",self.health)]:
            self.step(name, action)
        self.state["stage"]="ready";self.state.pop("last_error",None)
        save_state(self.paths.state_file,self.state)
        print(f"Installation vérifiée : https://{self.config['domain']}/login")
        print("Identifiants initiaux conservés dans /root/syscohada-identifiants.txt (lecture administrateur uniquement).")


def collect_config(path: str | None, existing: dict[str, Any] | None = None) -> dict[str, Any]:
    if path:
        try: values=json.loads(Path(path).read_text())
        except (OSError,ValueError): raise DeploymentError("Configuration JSON absente ou illisible.") from None
        return validate_config(values)
    if existing: return validate_config(existing["config"])
    if not sys.stdin.isatty(): raise DeploymentError("Fournir --config ou utiliser un terminal interactif.")
    values={"domain":input("Domaine (ex. dsf.exemple.com) : ").strip(),
            "email":input("Email administrateur et certificat : ").strip(),
            "company":input("Nom de l’entreprise : ").strip(),
            "expected_ipv4":input("IPv4 publique du VPS Hostinger : ").strip(),
            "accept_acme_terms":False}
    print("Le certificat public transmettra le domaine et cet email à Let's Encrypt.")
    print("Conditions ACME : https://letsencrypt.org/repository/")
    values["accept_acme_terms"]=input("Acceptez-vous ces conditions pour demander le certificat ? [oui/non] : ").strip().lower()=="oui"
    return validate_config(values)


def show_status(paths: DeployPaths, runner: CommandRunner) -> int:
    if not paths.state_file.exists(): print("Aucune installation gérée détectée.");return 1
    state=load_state(paths.state_file)
    health="not_checked"
    if state.get("stage")=="ready":
        result=runner.run(["curl","--fail","--silent","--show-error","--max-time","15","--write-out","\n%{http_code}","https://"+state["config"]["domain"]+"/up"],sensitive=True,allow_failure=True,label="santé HTTPS")
        health="ok" if result.returncode==0 and result.stdout.rsplit("\n",1)[-1].strip()=="200" else "failed"
    print(json.dumps({"stage":state.get("stage"),"version":VERSION,"url":"https://"+state["config"]["domain"]+"/login","maintenance":paths.maintenance.exists(),"https_health":health},ensure_ascii=False,indent=2))
    return 0 if health=="ok" and not paths.maintenance.exists() else 2


def main(argv: list[str] | None = None) -> int:
    parser=argparse.ArgumentParser(description="Installer SYSCOHADA CM sur un VPS dédié Debian 13.")
    modes=parser.add_mutually_exclusive_group()
    modes.add_argument("--plan",action="store_true",help="vérifications sans modification (défaut)")
    modes.add_argument("--install",action="store_true",help="nouvelle installation")
    modes.add_argument("--resume",action="store_true",help="reprendre l’installation reconnue sans changer ses clés")
    modes.add_argument("--status",action="store_true",help="statut sans modification")
    parser.add_argument("--config",help="configuration JSON sans secret")
    args=parser.parse_args(argv)
    paths=DeployPaths();runner=CommandRunner();state=None;mutation_started=False
    try:
        if args.status: return show_status(paths,runner)
        if paths.state_file.exists(): state=load_state(paths.state_file)
        config=collect_config(args.config,state if args.resume else None)
        payload=load_payload(paths)
        if state and (state.get("config_fingerprint")!=config_fingerprint(config) or state.get("payload_sha256")!=payload["sha256"]):
            raise DeploymentError("La configuration ou le paquet diffère de l’installation reconnue ; aucune reprise automatique.")
        plan=build_plan(config,paths,runner,state)
        if not args.install and not args.resume:
            print(json.dumps(plan,ensure_ascii=False,indent=2));return 0 if plan["ready"] else 2
        if os.geteuid()!=0: raise DeploymentError("L’installation exige root via la console Hostinger ou sudo.")
        if args.resume and state is None: raise DeploymentError("Aucun état reconnu à reprendre.")
        if state and state.get("stage")=="ready": return show_status(paths,runner)
        if state and not args.resume: raise DeploymentError("Une tentative existe ; employer --resume après revue du statut.")
        if not plan["ready"]: raise DeploymentError("Précontrôle refusé : "+" ; ".join(plan["problems"]))
        if not config["accept_acme_terms"]: raise DeploymentError("Accepter explicitement les conditions ACME dans la configuration ou le terminal.")
        paths.state_dir.mkdir(mode=0o700,parents=True,exist_ok=True);paths.state_dir.chmod(0o700)
        with exclusive_lock(paths.state_dir/"deployment.lock"):
            # Another process may have completed between the read-only plan and this lock.
            locked_state=load_state(paths.state_file) if paths.state_file.exists() else None
            if locked_state is not None:
                if locked_state.get("config_fingerprint")!=config_fingerprint(config) or locked_state.get("payload_sha256")!=payload["sha256"]:
                    raise DeploymentError("État concurrent incompatible ; aucune modification effectuée.")
                if locked_state.get("stage")=="ready": return show_status(paths,runner)
                if not args.resume: raise DeploymentError("Une tentative existe déjà ; employer --resume.")
                state=locked_state
            elif state is not None:
                raise DeploymentError("L’état reconnu a disparu ; intervention manuelle nécessaire.")
            if state is None:
                state=new_state(config,payload["sha256"]);save_state(paths.state_file,state)
            mutation_started=True
            Installer(config,paths,runner,state).install()
        return 0
    except (DeploymentError,OSError) as exc:
        if mutation_started and state is not None and os.geteuid()==0:
            try:
                state["stage"]="failed";state["last_error"]="Deployment step failed; inspect the reported stage."
                save_state(paths.state_file,state)
                if paths.base.exists(): atomic_write(paths.maintenance,"Installation non validée.\n",mode=0o644)
            except (OSError,DeploymentError): pass
        detail = str(exc) if isinstance(exc, DeploymentError) else "Accès système refusé ou fichier indisponible."
        print("Déploiement interrompu : "+detail,file=sys.stderr)
        print("Aucune base n’a été supprimée. Corriger la cause puis utiliser --resume si un état existe.",file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrompu. Les ressources et clés reconnues sont conservées pour --resume.",file=sys.stderr);return 130


if __name__=="__main__":
    raise SystemExit(main())
