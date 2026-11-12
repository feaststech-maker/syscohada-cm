"""Defensive, standard-library helpers for the SYSCOHADA Hostinger installer.

No server command is executed at import time. This module deliberately does not
download code, change DNS, extract an arbitrary destination root or print secrets.
"""
from __future__ import annotations

import base64
import contextlib
import datetime as dt
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import socket
import stat
from string import Template
import tempfile
from typing import Any, Iterator, Mapping
import unicodedata
import uuid
import zipfile
import zlib


class DeploymentError(RuntimeError):
    """Operator-facing error; messages must contain neither credentials nor SQL."""


ROOT_FOLDER = "syscohada-cm-laravel"
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 20_000
MAX_EXPANDED_BYTES = 256 * 1024 * 1024
MAX_ENTRY_BYTES = 32 * 1024 * 1024
MAX_EXPANSION_RATIO = 200
CONFIG_FIELDS = {"domain", "email", "company", "expected_ipv4", "accept_acme_terms"}


def validate_config(data: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(data, dict) or set(data) - CONFIG_FIELDS:
        raise DeploymentError("Configuration inconnue : utilisez les champs du modèle fourni.")
    for name in ("domain", "email", "company", "expected_ipv4"):
        if not isinstance(data.get(name), str) or not data[name].strip():
            raise DeploymentError(f"Paramètre obligatoire : {name}.")
    domain = data["domain"].strip().removesuffix(".").lower()
    if not domain.isascii() or len(domain) > 253 or "." not in domain:
        raise DeploymentError("Le domaine doit être un nom DNS ASCII complet, sans URL.")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise DeploymentError("Le domaine doit être un nom DNS, pas une adresse IP.")
    labels = domain.split(".")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in labels):
        raise DeploymentError("Nom de domaine invalide.")
    if labels[-1].isdigit() or len(labels[-1]) < 2 or labels[-1] in {"localhost", "local", "internal"}:
        raise DeploymentError("Un domaine public complet est nécessaire pour HTTPS.")
    email = data["email"].strip().lower()
    if not email.isascii() or len(email) > 254 or not re.fullmatch(
        r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,63}", email
    ) or ".." in email or email.startswith(".") or ".@" in email:
        raise DeploymentError("Adresse email invalide.")
    company = unicodedata.normalize("NFC", data["company"].strip())
    if len(company) > 200 or any(unicodedata.category(c).startswith("C") for c in data["company"]):
        raise DeploymentError("Nom d’entreprise invalide : texte sans caractère de contrôle, 200 caractères maximum.")
    try:
        address = ipaddress.IPv4Address(data["expected_ipv4"].strip())
    except (ValueError, ipaddress.AddressValueError):
        raise DeploymentError("Adresse IPv4 du VPS invalide.") from None
    if not address.is_global or address.is_multicast:
        raise DeploymentError("Renseignez l’adresse IPv4 publique du VPS Hostinger.")
    accepted = data.get("accept_acme_terms", False)
    if not isinstance(accepted, bool):
        raise DeploymentError("accept_acme_terms doit être true ou false.")
    return {"domain": domain, "email": email, "company": company,
            "expected_ipv4": str(address), "accept_acme_terms": accepted}


def config_fingerprint(config: Mapping[str, Any]) -> str:
    normalised = validate_config(dict(config))
    canonical = json.dumps(normalised, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def resolve_domain(domain: str) -> set[str]:
    try:
        records = socket.getaddrinfo(domain, 443, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
        result = {str(ipaddress.ip_address(record[4][0])) for record in records}
    except (socket.gaierror, OSError, ValueError):
        raise DeploymentError("Le domaine ne peut pas être résolu. Vérifiez les enregistrements DNS.") from None
    if not result:
        raise DeploymentError("Aucun enregistrement A ou AAAA trouvé pour le domaine.")
    return result


def validate_dns(config: Mapping[str, Any], local_addresses: Any = None) -> dict[str, Any]:
    normalised = validate_config(dict(config))
    actual = resolve_domain(normalised["domain"])
    allowed = {normalised["expected_ipv4"]}
    for raw in local_addresses or ():
        try:
            address = ipaddress.ip_address(str(raw).split("%", 1)[0])
        except ValueError:
            raise DeploymentError("Inventaire réseau local invalide.") from None
        if address.is_global and not address.is_multicast:
            allowed.add(str(address))
    if normalised["expected_ipv4"] not in actual:
        raise DeploymentError("L’enregistrement A doit pointer vers l’IPv4 du VPS indiquée avant le déploiement.")
    if actual - allowed:
        raise DeploymentError("Un enregistrement A ou AAAA pointe vers un autre serveur. Corrigez ce même sous-domaine avant de continuer.")
    return {"ok": True, "domain": normalised["domain"], "addresses": sorted(actual),
            "expected_ipv4": normalised["expected_ipv4"]}


def sha256_file(path: str | Path) -> str:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise DeploymentError("Fichier de paquet absent ou non régulier.")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_parents(path: Path) -> None:
    # lstat each existing component rather than trusting resolve() through symlinks.
    absolute = Path(os.path.abspath(path))
    for current in (absolute, *absolute.parents):
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise DeploymentError("Un répertoire de déploiement est un lien ou un fichier : opération refusée.")


def atomic_write(path: str | Path, data: str | bytes, mode: int = 0o600) -> None:
    path = Path(os.path.abspath(path))
    if not 0 <= mode <= 0o777:
        raise DeploymentError("Permissions de fichier invalides.")
    _safe_parents(path.parent)
    path.parent.mkdir(parents=True, exist_ok=True)
    _safe_parents(path.parent)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise DeploymentError("Destination de fichier non régulière.")
    descriptor, temporary = tempfile.mkstemp(prefix=".syscohada-write-", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        payload = data.encode("utf-8") if isinstance(data, str) else data
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        # A symlink introduced concurrently must not be replaced silently either.
        if path.is_symlink():
            raise DeploymentError("Destination de fichier changée pendant l’écriture.")
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def render_template(text: str, values: Mapping[str, Any]) -> str:
    substitutions = {}
    for name, value in values.items():
        if not isinstance(name, str) or not isinstance(value, (str, int)):
            raise DeploymentError("Valeur de modèle invalide.")
        value = str(value)
        if any(c in value for c in ("\0", "\r", "\n")):
            raise DeploymentError("Caractère interdit dans un modèle de configuration.")
        substitutions[name] = value
    try:
        return Template(text).substitute(substitutions)
    except (KeyError, ValueError):
        raise DeploymentError("Modèle de configuration incomplet.") from None


def _check_zip_name(name: str) -> tuple[str, ...]:
    if not name or "\0" in name or "\\" in name or name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        raise DeploymentError("Chemin interdit dans le paquet.")
    if len(name) > 1024 or any(unicodedata.category(c).startswith("C") for c in name):
        raise DeploymentError("Nom de fichier interdit dans le paquet.")
    stripped = name[:-1] if name.endswith("/") else name
    parts = tuple(stripped.split("/"))
    if any(part in ("", ".", "..") for part in parts) or parts[0] != ROOT_FOLDER:
        raise DeploymentError("Le paquet doit contenir uniquement la racine Laravel prévue.")
    if any(part == ".env" or part.startswith(".env.") and part != ".env.example" for part in parts):
        raise DeploymentError("Le paquet contient une configuration privée interdite.")
    if name.lower().endswith((".sqlite", ".sqlite3", ".db")):
        raise DeploymentError("Le paquet contient une base locale interdite.")
    if len(parts) > 1 and parts[1] == "storage" and not name.endswith("/") and parts[-1] != ".gitignore":
        raise DeploymentError("Le paquet contient des fichiers de stockage privés.")
    return parts


def safe_extract_app(zip_path: str | Path, destination: str | Path, expected_sha256: str) -> Path:
    zip_path = Path(zip_path)
    if not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise DeploymentError("Empreinte du paquet invalide.")
    if not zip_path.is_file() or zip_path.is_symlink() or not 0 < zip_path.stat().st_size <= MAX_ARCHIVE_BYTES:
        raise DeploymentError("Taille ou type du paquet invalide.")
    if not secrets.compare_digest(sha256_file(zip_path), expected_sha256):
        raise DeploymentError("Le paquet ne correspond pas à l’empreinte attendue.")
    destination = Path(os.path.abspath(destination))
    _safe_parents(destination)
    destination.mkdir(parents=True, exist_ok=True)
    target = destination / ROOT_FOLDER
    if target.exists() or target.is_symlink():
        raise DeploymentError("La destination d’extraction existe déjà ; aucun contenu n’a été remplacé.")
    staging: Path | None = None
    try:
        with zipfile.ZipFile(zip_path, "r") as archive:
            entries = archive.infolist()
            if not entries or len(entries) > MAX_ENTRIES:
                raise DeploymentError("Nombre de fichiers du paquet excessif.")
            seen: set[str] = set()
            total = 0
            files: set[str] = set()
            for info in entries:
                # ZipInfo truncates filename at a NUL; inspect its original value
                # before trusting the normalised name used for extraction.
                _check_zip_name(info.orig_filename)
                parts = _check_zip_name(info.filename)
                canonical = "/".join(parts)
                if canonical in seen:
                    raise DeploymentError("Le paquet contient un chemin en double.")
                seen.add(canonical)
                if info.flag_bits & 1 or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise DeploymentError("Compression ou chiffrement ZIP non pris en charge.")
                unix_mode = (info.external_attr >> 16) & 0xFFFF
                kind = stat.S_IFMT(unix_mode)
                if kind not in (0, stat.S_IFDIR, stat.S_IFREG) or (kind == stat.S_IFDIR) != info.is_dir() and kind != 0:
                    raise DeploymentError("Lien ou fichier spécial interdit dans le paquet.")
                if info.file_size > MAX_ENTRY_BYTES or info.compress_size < 0:
                    raise DeploymentError("Un fichier du paquet dépasse la limite.")
                total += info.file_size
                if total > MAX_EXPANDED_BYTES or total > MAX_EXPANSION_RATIO * zip_path.stat().st_size:
                    raise DeploymentError("Expansion du paquet excessive.")
                if not info.is_dir():
                    files.add(canonical)
            for name in seen:
                for parent in PurePosixPath(name).parents:
                    if str(parent) in files:
                        raise DeploymentError("Un fichier du paquet masque un répertoire.")
            required = {f"{ROOT_FOLDER}/artisan", f"{ROOT_FOLDER}/public/index.php", f"{ROOT_FOLDER}/composer.lock", f"{ROOT_FOLDER}/vendor/autoload.php"}
            if not required <= files:
                raise DeploymentError("Le paquet Laravel est incomplet.")
            staging = Path(tempfile.mkdtemp(prefix=".syscohada-unpack-", dir=destination))
            actual_total = 0
            for info in entries:
                output = staging.joinpath(*_check_zip_name(info.filename))
                if info.is_dir():
                    output.mkdir(mode=0o755, parents=True, exist_ok=True)
                    continue
                output.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(output, flags, 0o644)
                os.fchmod(descriptor, 0o644)
                with archive.open(info, "r") as source, os.fdopen(descriptor, "wb") as sink:
                    actual_size = 0
                    while chunk := source.read(1024 * 1024):
                        actual_size += len(chunk); actual_total += len(chunk)
                        if actual_size > MAX_ENTRY_BYTES or actual_total > MAX_EXPANDED_BYTES:
                            raise DeploymentError("Expansion réelle du paquet excessive.")
                        sink.write(chunk)
                    if actual_size != info.file_size:
                        raise DeploymentError("Taille réelle d’un fichier différente du manifeste ZIP.")
            # The installer may run with umask 077 for its secrets. Code must
            # nevertheless become readable by the separate PHP-FPM identity.
            for directory in (staging / ROOT_FOLDER, *(p for p in (staging / ROOT_FOLDER).rglob("*") if p.is_dir())):
                os.chmod(directory, 0o755)
            if target.exists() or target.is_symlink():
                raise DeploymentError("La destination d’extraction a changé.")
            os.rename(staging / ROOT_FOLDER, target)
        return target
    except (zipfile.BadZipFile, RuntimeError, OSError, EOFError, zlib.error) as exc:
        if isinstance(exc, DeploymentError):
            raise
        raise DeploymentError("Le paquet ne peut pas être extrait en sécurité.") from None
    finally:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)


def new_state(config: Mapping[str, Any], payload_sha: str) -> dict[str, Any]:
    clean = validate_config(dict(config))
    if not isinstance(payload_sha, str) or not re.fullmatch(r"[a-f0-9]{64}", payload_sha):
        raise DeploymentError("Empreinte de version invalide.")
    return {
        "schema_version": 1,
        "config": clean,
        "config_fingerprint": config_fingerprint(clean),
        "payload_sha256": payload_sha,
        "stage": "planned",
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "tenant_id": str(uuid.uuid4()), "actor_id": str(uuid.uuid4()),
        "secrets": {
            "app_key": "base64:" + base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
            "db_password": secrets.token_hex(32),
            "admin_password": secrets.token_urlsafe(24) + "A1",
        },
    }


def _validate_state(state: Any) -> dict[str, Any]:
    if not isinstance(state, dict) or state.get("schema_version") != 1:
        raise DeploymentError("Version du fichier d’état non prise en charge.")
    clean = validate_config(state.get("config"))
    payload_sha = state.get("payload_sha256")
    if state.get("config_fingerprint") != config_fingerprint(clean) or not isinstance(payload_sha, str) or not re.fullmatch(r"[a-f0-9]{64}", payload_sha):
        raise DeploymentError("Le fichier d’état est incohérent.")
    try:
        stage = state["stage"]
        if not isinstance(stage, str) or not 1 <= len(stage) <= 128 or any(unicodedata.category(c).startswith("C") for c in stage):
            raise ValueError
        created = dt.datetime.fromisoformat(state["created_at"])
        if created.tzinfo is None or created.utcoffset() is None:
            raise ValueError
        uuid.UUID(state["tenant_id"]); uuid.UUID(state["actor_id"])
        secret = state["secrets"]
        raw = base64.b64decode(secret["app_key"].removeprefix("base64:"), validate=True)
        if not secret["app_key"].startswith("base64:") or len(raw) != 32 or not re.fullmatch(r"[a-f0-9]{64}", secret["db_password"]):
            raise ValueError
        admin = secret["admin_password"]
        if not isinstance(admin, str) or not 12 <= len(admin.encode()) <= 72 or not re.fullmatch(r"[A-Za-z0-9_-]+", admin) or not re.search(r"[A-Za-z]", admin) or not re.search(r"[0-9]", admin):
            raise ValueError
    except (KeyError, TypeError, ValueError, AttributeError):
        raise DeploymentError("Secrets ou identités du fichier d’état invalides.") from None
    return state


def save_state(path: str | Path, state: Mapping[str, Any]) -> None:
    data = _validate_state(dict(state))
    previous = load_state(path)
    if previous is not None:
        immutable = ("config_fingerprint", "payload_sha256", "tenant_id", "actor_id", "created_at")
        if any(previous.get(key) != data.get(key) for key in immutable) or any(
            data["secrets"].get(key) != value for key, value in previous["secrets"].items()
        ):
            raise DeploymentError("La reprise ne peut modifier la configuration, la version ou les secrets d’une installation existante.")
    atomic_write(path, json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2) + "\n", 0o600)


def load_state(path: str | Path) -> dict[str, Any] | None:
    path = Path(path)
    if not path.exists() and not path.is_symlink():
        return None
    try:
        _safe_parents(path.parent)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "r", encoding="utf-8") as source:
            details = os.fstat(source.fileno())
            if not stat.S_ISREG(details.st_mode) or stat.S_IMODE(details.st_mode) & 0o077 or details.st_uid not in (0, os.geteuid()) or details.st_size > 1024 * 1024:
                raise DeploymentError("Le fichier d’état doit être privé, régulier et appartenir à l’administrateur.")
            return _validate_state(json.load(source))
    except DeploymentError:
        raise
    except (OSError, json.JSONDecodeError, UnicodeError):
        raise DeploymentError("Le fichier d’état ne peut pas être lu en sécurité.") from None


@contextlib.contextmanager
def exclusive_lock(path: str | Path) -> Iterator[None]:
    path = Path(path)
    _safe_parents(path.parent)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode) or stat.S_IMODE(details.st_mode) & 0o077 or details.st_uid not in (0, os.geteuid()):
                raise DeploymentError("Verrou de déploiement non conforme.")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise DeploymentError("Un autre déploiement est déjà en cours.") from None
            yield
        finally:
            os.close(descriptor)
    except OSError:
        raise DeploymentError("Le verrou de déploiement ne peut pas être ouvert en sécurité.") from None


def redact(text: str, secret_values: Any = ()) -> str:
    result = str(text)
    if isinstance(secret_values, Mapping):
        secret_values = secret_values.values()
    for value in sorted((str(v) for v in secret_values if v), key=len, reverse=True):
        result = result.replace(value, "[SECRET]")
    # Additional defence for common diagnostic output. Never treat this as a
    # substitute for not logging a sensitive command or SQL input at all.
    result = re.sub(r"(?im)\b(APP_KEY|DB_PASSWORD|ADMIN_PASSWORD|PGPASSWORD)\s*=\s*[^\r\n]*", r"\1=[SECRET]", result)
    return result
