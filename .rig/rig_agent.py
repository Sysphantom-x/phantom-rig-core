#!/usr/bin/env python3
"""rig_agent: the on-node half of rigctl.

Runs on the GitHub Actions runner (Windows or Ubuntu) and provides:

* an authenticated control API bound to the node's Tailscale IP only
  (status / backup / web desktop / graceful stop),
* encrypted workspace snapshots (AES-256-GCM, chunked STREAM construction,
  scrypt KDF) stored as release assets in the private rig repository,
* live state hand-off between an old and a new runner during migration,
* a keep-alive watchdog that aborts rogue shutdowns, syncs the workspace
  periodically and (optionally) re-dispatches itself before the 6h limit.

Only the Python standard library is required, plus ``cryptography`` for the
state snapshots (installed by the workflow from PyPI / Ubuntu's archive).
Compatible with Python 3.9+.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import hmac
import io
import json
import os
import platform
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, BinaryIO, Callable, Dict, List, Optional, Tuple

AGENT_VERSION = "1.0.0"
DEFAULT_PORT = 7077
WEB_PORT = 6080
NOVNC_VERSION = "v1.5.0"
IS_WINDOWS = os.name == "nt"


def log(msg: str) -> None:
    print(f"[rig {time.strftime('%H:%M:%S')}] {msg}", flush=True)


def gh_warning(msg: str) -> None:
    # GitHub Actions workflow command: surfaces as an annotation on the run.
    print(f"::warning::{msg}", flush=True)


def _truthy(value: Optional[str]) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _int(value: Optional[str], default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
@dataclass
class AgentConfig:
    kind: str = "vps"  # "rig" (windows) | "vps" (ubuntu)
    os_name: str = "ubuntu"
    workflow: str = "vps.yml"
    workspace: Path = Path("/root/workspace")
    hostname: str = ""
    run_id: str = "0"
    repo: str = ""
    api_url: str = "https://api.github.com"
    ref: str = "main"
    github_token: str = ""
    agent_token: str = ""
    state_key: str = ""
    started_at: float = 0.0
    timeout_min: int = 350
    migrate_at_min: int = 330
    hard_stop_min: int = 344
    sync_interval_min: int = 30
    keepalive: bool = False
    chain: int = 0
    max_chain: int = 3
    restore: bool = True
    handoff_from: str = ""
    web: bool = False
    runner: str = ""
    packages: str = ""
    rdp_user: str = ""
    port: int = DEFAULT_PORT
    bind: str = ""
    keep_snapshots: int = 3

    @classmethod
    def from_env(cls, env: Optional[Dict[str, str]] = None) -> "AgentConfig":
        e = dict(os.environ if env is None else env)
        kind = e.get("RIG_KIND", "rig" if IS_WINDOWS else "vps")
        run_id = e.get("GITHUB_RUN_ID", "0")
        default_ws = r"C:\Workspace" if kind == "rig" else "/root/workspace"
        return cls(
            kind=kind,
            os_name=e.get("RIG_OS", "windows" if kind == "rig" else "ubuntu"),
            workflow=e.get("RIG_WORKFLOW", "rig.yml" if kind == "rig" else "vps.yml"),
            workspace=Path(e.get("RIG_WORKSPACE") or default_ws),
            hostname=e.get("RIG_HOSTNAME") or f"phantom-{kind}-{run_id}",
            run_id=run_id,
            repo=e.get("GITHUB_REPOSITORY", ""),
            api_url=e.get("GITHUB_API_URL", "https://api.github.com").rstrip("/"),
            ref=e.get("GITHUB_REF_NAME", "main"),
            github_token=e.get("GITHUB_TOKEN", ""),
            agent_token=e.get("RIG_AGENT_TOKEN", ""),
            state_key=e.get("RIG_STATE_KEY", ""),
            started_at=float(e.get("RIG_STARTED_AT") or time.time()),
            timeout_min=_int(e.get("RIG_TIMEOUT_MIN"), 350),
            migrate_at_min=_int(e.get("RIG_MIGRATE_AT_MIN"), 330),
            hard_stop_min=_int(e.get("RIG_HARD_STOP_MIN"), 344),
            sync_interval_min=_int(e.get("RIG_SYNC_INTERVAL_MIN"), 30),
            keepalive=_truthy(e.get("RIG_KEEPALIVE")),
            chain=_int(e.get("RIG_CHAIN"), 0),
            max_chain=_int(e.get("RIG_MAX_CHAIN"), 3),
            restore=_truthy(e.get("RIG_RESTORE", "true")),
            handoff_from=(e.get("RIG_HANDOFF_FROM") or "").strip(),
            web=_truthy(e.get("RIG_WEB")),
            runner=e.get("RIG_RUNNER", ""),
            packages=e.get("RIG_PACKAGES", ""),
            rdp_user=e.get("RIG_RDP_USER", ""),
            port=_int(e.get("RIG_AGENT_PORT"), DEFAULT_PORT),
            bind=e.get("TAILSCALE_IP", ""),
            keep_snapshots=max(1, _int(e.get("RIG_KEEP_SNAPSHOTS"), 3)),
        )

    def __post_init__(self) -> None:
        if not self.hostname:
            self.hostname = self.peer_hostname(self.run_id)

    @property
    def deadline(self) -> float:
        return self.started_at + self.timeout_min * 60

    def peer_hostname(self, run_id: str) -> str:
        return f"phantom-{self.kind}-{run_id}"


# --------------------------------------------------------------------------- #
# Encrypted snapshot format (shared with rigctl for `rigctl state pull`)
#
#   header = MAGIC | n_log2 | r | p | chunk_size(u32 BE) | salt(16) | prefix(7)
#   chunk_i = AES-256-GCM(key, nonce = prefix | i (u32 BE) | last_flag, aad = header)
#
# The per-chunk "last" flag makes truncation detectable (STREAM construction).
# --------------------------------------------------------------------------- #
MAGIC = b"RIGSTATE1"
TAG_LEN = 16
CHUNK_SIZE = 1 << 20
SCRYPT_N_LOG2 = 15
HEADER_LEN = len(MAGIC) + 3 + 4 + 16 + 7


class StateError(Exception):
    pass


def _aead(key: bytes):
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:  # pragma: no cover - environment specific
        raise StateError("python package 'cryptography' is required for state snapshots") from exc
    return AESGCM(key)


def derive_key(passphrase: str, salt: bytes, n_log2: int = SCRYPT_N_LOG2, r: int = 8, p: int = 1) -> bytes:
    if not passphrase:
        raise StateError("RIG_STATE_KEY is empty")
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    return Scrypt(salt=salt, length=32, n=2**n_log2, r=r, p=p).derive(passphrase.encode("utf-8"))


def _nonce(prefix: bytes, counter: int, last: bool) -> bytes:
    if counter >= 2**32:
        raise StateError("snapshot too large")
    return prefix + counter.to_bytes(4, "big") + (b"\x01" if last else b"\x00")


class EncryptWriter:
    """Write-only file object that encrypts everything written to ``raw``."""

    def __init__(self, raw: BinaryIO, passphrase: str, *, chunk_size: int = CHUNK_SIZE, n_log2: int = SCRYPT_N_LOG2):
        salt, prefix = os.urandom(16), os.urandom(7)
        self.header = MAGIC + bytes([n_log2, 8, 1]) + chunk_size.to_bytes(4, "big") + salt + prefix
        self._aead = _aead(derive_key(passphrase, salt, n_log2))
        self._raw, self._prefix, self._chunk = raw, prefix, chunk_size
        self._buf = bytearray()
        self._counter = 0
        self._closed = False
        self.bytes_in = 0
        raw.write(self.header)

    def _emit(self, data: bytes, last: bool) -> None:
        ct = self._aead.encrypt(_nonce(self._prefix, self._counter, last), bytes(data), self.header)
        self._raw.write(ct)
        self._counter += 1

    def write(self, data: bytes) -> int:
        if self._closed:
            raise ValueError("write to closed EncryptWriter")
        self._buf += data
        self.bytes_in += len(data)
        # Keep at least one byte buffered so the final chunk is always flagged "last".
        while len(self._buf) > self._chunk:
            self._emit(self._buf[: self._chunk], last=False)
            del self._buf[: self._chunk]
        return len(data)

    def flush(self) -> None:
        self._raw.flush()

    def close(self) -> None:
        if not self._closed:
            self._emit(self._buf, last=True)
            self._buf.clear()
            self._closed = True
            self._raw.flush()

    # file-object protocol niceties for gzip/tarfile
    def writable(self) -> bool:
        return True

    def readable(self) -> bool:
        return False

    def seekable(self) -> bool:
        return False


def _read_exact(raw: BinaryIO, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        chunk = raw.read(n - len(out))
        if not chunk:
            break
        out += chunk
    return bytes(out)


class DecryptReader:
    """Read-only file object that authenticates and decrypts a snapshot stream."""

    def __init__(self, raw: BinaryIO, passphrase: str):
        header = _read_exact(raw, HEADER_LEN)
        if len(header) != HEADER_LEN or not header.startswith(MAGIC):
            raise StateError("not a rigctl snapshot (bad magic)")
        o = len(MAGIC)
        n_log2, r, p = header[o], header[o + 1], header[o + 2]
        self._chunk = int.from_bytes(header[o + 3 : o + 7], "big")
        salt = header[o + 7 : o + 23]
        self._prefix = header[o + 23 : o + 30]
        if not (10 <= n_log2 <= 22) or not (0 < self._chunk <= 64 << 20):
            raise StateError("snapshot header has invalid parameters")
        self.header = header
        self._aead = _aead(derive_key(passphrase, salt, n_log2, r, p))
        self._raw = raw
        self._carry = b""
        self._counter = 0
        self._done = False
        self._plain = bytearray()

    def _next_chunk(self) -> bytes:
        from cryptography.exceptions import InvalidTag

        need = self._chunk + TAG_LEN
        data = self._carry + _read_exact(self._raw, need + 1 - len(self._carry))
        if len(data) <= need:
            ct, self._carry, last = data, b"", True
        else:
            ct, self._carry, last = data[:need], data[need:], False
        if len(ct) < TAG_LEN:
            raise StateError("snapshot is truncated")
        try:
            pt = self._aead.decrypt(_nonce(self._prefix, self._counter, last), ct, self.header)
        except InvalidTag:
            raise StateError("snapshot authentication failed (wrong RIG_STATE_KEY or corrupted/truncated data)") from None
        self._counter += 1
        self._done = last
        return pt

    def read(self, n: int = -1) -> bytes:
        while not self._done and (n < 0 or len(self._plain) < n):
            self._plain += self._next_chunk()
        if n < 0:
            n = len(self._plain)
        out = bytes(self._plain[:n])
        del self._plain[:n]
        return out

    def readable(self) -> bool:
        return True

    def close(self) -> None:
        pass


def iter_workspace(workspace: Path):
    for root, dirs, files in os.walk(workspace):
        dirs.sort()
        for name in sorted(dirs) + sorted(files):
            yield Path(root) / name


def workspace_has_files(workspace: Path) -> bool:
    if not workspace.is_dir():
        return False
    return any(files for _root, _dirs, files in os.walk(workspace))


def write_snapshot(workspace: Path, out: BinaryIO, passphrase: str, *, chunk_size: int = CHUNK_SIZE) -> Dict[str, int]:
    """tar | gzip | encrypt the workspace into ``out``. Unreadable files are skipped."""
    enc = EncryptWriter(out, passphrase, chunk_size=chunk_size)
    files = skipped = 0
    with gzip.GzipFile(fileobj=enc, mode="wb", compresslevel=6, mtime=0) as gz:  # type: ignore[arg-type]
        with tarfile.open(fileobj=gz, mode="w|", format=tarfile.PAX_FORMAT) as tar:
            for path in iter_workspace(workspace):
                arcname = path.relative_to(workspace).as_posix()
                try:
                    tar.add(str(path), arcname=arcname, recursive=False)
                    if path.is_file():
                        files += 1
                except OSError as exc:  # locked / vanished files
                    skipped += 1
                    log(f"skip {arcname}: {exc.__class__.__name__}")
    enc.close()
    return {"files": files, "skipped": skipped, "plain_bytes": enc.bytes_in}


def _safe_members(tar: tarfile.TarFile, dest: Path):
    root = dest.resolve()
    for member in tar:
        target = (dest / member.name).resolve()
        if root != target and root not in target.parents:
            log(f"refusing to extract outside workspace: {member.name}")
            continue
        if member.islnk() or member.issym():
            link = (target.parent / member.linkname).resolve()
            if root != link and root not in link.parents:
                log(f"refusing link escaping workspace: {member.name}")
                continue
        if member.isdev():
            continue
        yield member


def read_snapshot(src: BinaryIO, dest: Path, passphrase: str) -> int:
    """decrypt | gunzip | untar ``src`` into ``dest``. Returns number of entries."""
    dest.mkdir(parents=True, exist_ok=True)
    dec = DecryptReader(src, passphrase)
    count = 0
    with gzip.GzipFile(fileobj=dec, mode="rb") as gz:  # type: ignore[arg-type]
        with tarfile.open(fileobj=gz, mode="r|") as tar:
            for member in _safe_members(tar, dest):
                if hasattr(tarfile, "data_filter"):
                    tar.extract(member, str(dest), filter="data")
                else:  # pragma: no cover - very old Pythons
                    tar.extract(member, str(dest))
                count += 1
    return count


# --------------------------------------------------------------------------- #
# Minimal GitHub REST client (stdlib only)
# --------------------------------------------------------------------------- #
class GitHubError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(f"GitHub API {status}: {message}")
        self.status = status


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


class _Slice:
    """Read ``length`` bytes from ``f`` starting at ``offset`` while hashing them."""

    def __init__(self, f: BinaryIO, offset: int, length: int):
        f.seek(offset)
        self._f, self._left = f, length
        self.sha256 = hashlib.sha256()

    def read(self, n: int = -1) -> bytes:
        if self._left <= 0:
            return b""
        n = self._left if n is None or n < 0 else min(n, self._left)
        data = self._f.read(n)
        self._left -= len(data)
        self.sha256.update(data)
        return data


class GitHubAPI:
    def __init__(self, token: str, repo: str, api_url: str = "https://api.github.com"):
        self.token, self.repo, self.api_url = token, repo, api_url.rstrip("/")
        self._noredirect = urllib.request.build_opener(_NoRedirect)

    def _headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        h = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": f"rig-agent/{AGENT_VERSION}",
        }
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        h.update(extra or {})
        return h

    def request(
        self,
        method: str,
        path: str,
        *,
        body: Any = None,
        data: Any = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 60,
        retries: int = 3,
    ) -> Tuple[int, bytes]:
        url = path if path.startswith("http") else f"{self.api_url}{path}"
        payload = json.dumps(body).encode() if body is not None else data
        hdrs = self._headers(headers)
        if body is not None:
            hdrs["Content-Type"] = "application/json"
        for attempt in range(retries):
            req = urllib.request.Request(url, data=payload, method=method, headers=hdrs)
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return resp.status, resp.read()
            except urllib.error.HTTPError as exc:
                text = exc.read().decode("utf-8", "replace")[:500]
                if exc.code >= 500 and attempt + 1 < retries and not hasattr(payload, "read"):
                    time.sleep(2 * (attempt + 1))
                    continue
                raise GitHubError(exc.code, text) from None
            except urllib.error.URLError as exc:
                if attempt + 1 < retries and not hasattr(payload, "read"):
                    time.sleep(2 * (attempt + 1))
                    continue
                raise GitHubError(0, str(exc.reason)) from None
        raise GitHubError(0, "unreachable")  # pragma: no cover

    def json(self, method: str, path: str, **kw: Any) -> Any:
        _status, raw = self.request(method, path, **kw)
        return json.loads(raw) if raw else None

    # -- releases ---------------------------------------------------------- #
    def release_by_tag(self, tag: str) -> Optional[dict]:
        try:
            return self.json("GET", f"/repos/{self.repo}/releases/tags/{urllib.parse.quote(tag)}")
        except GitHubError as exc:
            if exc.status == 404:
                return None
            raise

    def create_release(self, tag: str, name: str, body: str) -> dict:
        return self.json(
            "POST",
            f"/repos/{self.repo}/releases",
            body={"tag_name": tag, "name": name, "body": body, "prerelease": True, "make_latest": "false"},
        )

    def list_assets(self, release_id: int) -> List[dict]:
        assets: List[dict] = []
        page = 1
        while True:
            batch = self.json("GET", f"/repos/{self.repo}/releases/{release_id}/assets?per_page=100&page={page}")
            assets.extend(batch)
            if len(batch) < 100:
                return assets
            page += 1

    def upload_asset(self, release: dict, name: str, f: BinaryIO, offset: int, length: int) -> Tuple[dict, str]:
        base = release["upload_url"].split("{", 1)[0]
        url = f"{base}?name={urllib.parse.quote(name)}"
        last_exc: Optional[Exception] = None
        for attempt in range(3):
            body = _Slice(f, offset, length)
            try:
                _s, raw = self.request(
                    "POST",
                    url,
                    data=body,
                    headers={"Content-Type": "application/octet-stream", "Content-Length": str(length)},
                    timeout=1800,
                    retries=1,
                )
                return json.loads(raw), body.sha256.hexdigest()
            except GitHubError as exc:
                last_exc = exc
                if exc.status and exc.status < 500:
                    raise
                time.sleep(3 * (attempt + 1))
        raise last_exc  # type: ignore[misc]

    def delete_asset(self, asset_id: int) -> None:
        self.request("DELETE", f"/repos/{self.repo}/releases/assets/{asset_id}")

    def download_asset(self, asset_id: int, out: BinaryIO) -> int:
        url = f"{self.api_url}/repos/{self.repo}/releases/assets/{asset_id}"
        req = urllib.request.Request(url, headers=self._headers({"Accept": "application/octet-stream"}))
        try:
            resp = self._noredirect.open(req, timeout=1800)
        except urllib.error.HTTPError as exc:
            if exc.code not in (301, 302, 303, 307, 308):
                raise GitHubError(exc.code, exc.read().decode("utf-8", "replace")[:300]) from None
            # Storage URLs are pre-signed: never forward our token to them.
            location = exc.headers["Location"]
            resp = urllib.request.urlopen(
                urllib.request.Request(location, headers={"User-Agent": f"rig-agent/{AGENT_VERSION}"}), timeout=1800
            )
        total = 0
        with resp:
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    return total
                out.write(chunk)
                total += len(chunk)

    # -- actions ----------------------------------------------------------- #
    def dispatch(self, workflow: str, ref: str, inputs: Dict[str, str]) -> None:
        self.request(
            "POST", f"/repos/{self.repo}/actions/workflows/{workflow}/dispatches", body={"ref": ref, "inputs": inputs}
        )

    def find_run_by_title(self, workflow: str, needle: str) -> Optional[int]:
        data = self.json(
            "GET", f"/repos/{self.repo}/actions/workflows/{workflow}/runs?event=workflow_dispatch&per_page=20"
        )
        for run in data.get("workflow_runs", []):
            if needle and needle in (run.get("display_title") or ""):
                return int(run["id"])
        return None


# --------------------------------------------------------------------------- #
# Snapshot storage in GitHub Releases (private repo, encrypted blobs)
# --------------------------------------------------------------------------- #
PART_SIZE = 1900 * 1024 * 1024  # release assets are capped at 2 GiB each


class StateStore:
    def __init__(self, gh: GitHubAPI, kind: str, keep: int = 3, part_size: int = PART_SIZE):
        self.gh, self.kind, self.keep, self.part_size = gh, kind, keep, part_size
        self.tag = f"rig-state-{kind}"

    def release(self, create: bool = False) -> Optional[dict]:
        rel = self.gh.release_by_tag(self.tag)
        if rel is None and create:
            rel = self.gh.create_release(
                self.tag,
                f"rigctl state · {self.kind}",
                "Encrypted workspace snapshots managed by rigctl. Assets are AES-256-GCM encrypted; "
                "only holders of RIG_STATE_KEY can read them. Do not edit by hand.",
            )
        return rel

    def manifests(self, assets: List[dict]) -> List[dict]:
        pat = re.compile(rf"^{re.escape(self.kind)}-\d{{8}}T\d{{9}}Z-\d+\.json$")
        return sorted((a for a in assets if pat.match(a["name"])), key=lambda a: a["name"], reverse=True)

    def save(self, workspace: Path, passphrase: str, meta: Dict[str, Any], tmpdir: Optional[str] = None) -> dict:
        rel = self.release(create=True)
        assert rel is not None
        now = time.time()
        stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime(now)) + f"{int((now % 1) * 1000):03d}Z"
        base = f"{self.kind}-{stamp}-{meta.get('run_id', '0')}"
        with tempfile.TemporaryFile(dir=tmpdir) as tmp:
            stats = write_snapshot(workspace, tmp, passphrase)
            size = tmp.tell()
            parts = []
            offset, index = 0, 0
            while offset < size or (size == 0 and index == 0):
                length = min(self.part_size, size - offset)
                name = f"{base}.p{index:03d}"
                asset, digest = self.gh.upload_asset(rel, name, tmp, offset, length)
                parts.append({"name": name, "id": asset.get("id"), "size": length, "sha256": digest})
                offset += length
                index += 1
                if size == 0:
                    break
        manifest = {
            "format": 1,
            "kind": self.kind,
            "created_at": int(now),
            "size": size,
            "parts": parts,
            "agent_version": AGENT_VERSION,
            **stats,
            **meta,
        }
        blob = json.dumps(manifest, indent=2).encode()
        self.gh.upload_asset(rel, f"{base}.json", io.BytesIO(blob), 0, len(blob))
        self.prune(rel)
        manifest["name"] = base
        return manifest

    def prune(self, rel: dict) -> int:
        """Keep the newest ``keep`` snapshots. Assets newer than the oldest kept
        snapshot are never touched, so a concurrent upload from another node
        (whose manifest is not written yet) survives."""
        assets = self.gh.list_assets(rel["id"])
        kept = [m["name"][: -len(".json")] for m in self.manifests(assets)[: self.keep]]
        if not kept:
            return 0
        oldest_kept = min(kept)
        removed = 0
        for asset in assets:
            name = asset["name"]
            if not name.startswith(f"{self.kind}-"):
                continue
            base = name.rsplit(".", 1)[0]
            if base not in kept and base < oldest_kept:
                self.gh.delete_asset(asset["id"])
                removed += 1
        return removed

    def latest(self) -> Optional[Tuple[dict, dict, List[dict]]]:
        rel = self.release()
        if not rel:
            return None
        assets = self.gh.list_assets(rel["id"])
        manifests = self.manifests(assets)
        if not manifests:
            return None
        buf = io.BytesIO()
        self.gh.download_asset(manifests[0]["id"], buf)
        return json.loads(buf.getvalue()), manifests[0], assets

    def fetch(self, manifest: dict, assets: List[dict], out: BinaryIO) -> None:
        by_name = {a["name"]: a for a in assets}
        for part in manifest["parts"]:
            asset = by_name.get(part["name"])
            if asset is None:
                raise StateError(f"snapshot part missing: {part['name']}")
            hasher = _HashingWriter(out)
            self.gh.download_asset(asset["id"], hasher)
            if hasher.sha256.hexdigest() != part["sha256"]:
                raise StateError(f"checksum mismatch in {part['name']}")
        out.seek(0)

    def restore_latest(self, workspace: Path, passphrase: str, tmpdir: Optional[str] = None) -> Optional[dict]:
        found = self.latest()
        if not found:
            return None
        manifest, _asset, assets = found
        with tempfile.TemporaryFile(dir=tmpdir) as tmp:
            self.fetch(manifest, assets, tmp)
            manifest["restored_entries"] = read_snapshot(tmp, workspace, passphrase)
        return manifest


class _HashingWriter:
    def __init__(self, out: BinaryIO):
        self.out, self.sha256 = out, hashlib.sha256()

    def write(self, data: bytes) -> int:
        self.sha256.update(data)
        return self.out.write(data)


# --------------------------------------------------------------------------- #
# Host helpers: tailscale, metrics, anti-shutdown
# --------------------------------------------------------------------------- #
def run(cmd: List[str], *, timeout: float = 60, check: bool = False, env: Optional[dict] = None, input: Optional[bytes] = None) -> subprocess.CompletedProcess:
    proc = subprocess.run(cmd, capture_output=True, timeout=timeout, env=env, input=input)
    if check and proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()[-400:]
        raise RuntimeError(f"{' '.join(cmd[:3])}… exited {proc.returncode}: {err}")
    return proc


def tailscale_exe() -> str:
    if IS_WINDOWS:
        path = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Tailscale", "tailscale.exe")
        if os.path.exists(path):
            return path
    return shutil.which("tailscale") or "tailscale"


def tailscale_status() -> dict:
    proc = run([tailscale_exe(), "status", "--json"], timeout=20)
    if proc.returncode != 0:
        raise RuntimeError("tailscale status failed")
    return json.loads(proc.stdout or b"{}")


def tailscale_ipv4() -> str:
    proc = run([tailscale_exe(), "ip", "-4"], timeout=20)
    return proc.stdout.decode().strip().splitlines()[0] if proc.returncode == 0 and proc.stdout.strip() else ""


def find_peer(status: dict, hostname: str) -> Optional[dict]:
    for peer in (status.get("Peer") or {}).values():
        if peer.get("HostName") == hostname:
            return peer
    return None


def peer_ipv4(peer: dict) -> str:
    for ip in peer.get("TailscaleIPs") or []:
        if "." in ip:
            return ip
    return ""


class CpuSampler:
    def __init__(self) -> None:
        self._prev: Optional[Tuple[float, float]] = None

    @staticmethod
    def _times() -> Optional[Tuple[float, float]]:
        if IS_WINDOWS:
            import ctypes

            idle, kernel, user = ctypes.c_ulonglong(), ctypes.c_ulonglong(), ctypes.c_ulonglong()
            if not ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)):  # type: ignore[attr-defined]
                return None
            return float(idle.value), float(kernel.value + user.value)  # kernel time includes idle
        try:
            with open("/proc/stat") as fh:
                fields = [float(x) for x in fh.readline().split()[1:]]
        except OSError:
            return None
        idle = fields[3] + (fields[4] if len(fields) > 4 else 0.0)
        return idle, sum(fields)

    def percent(self) -> Optional[float]:
        cur = self._times()
        if cur is None:
            return None
        if self._prev is None:
            self._prev = cur
            time.sleep(0.25)
            cur = self._times() or cur
        prev, self._prev = self._prev, cur
        d_idle, d_total = cur[0] - prev[0], cur[1] - prev[1]
        if d_total <= 0:
            return 0.0
        return round(max(0.0, min(100.0, 100.0 * (1.0 - d_idle / d_total))), 1)


def memory_info() -> Dict[str, Any]:
    if IS_WINDOWS:
        import ctypes

        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        stat = MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))  # type: ignore[attr-defined]
        total, avail = int(stat.ullTotalPhys), int(stat.ullAvailPhys)
    else:
        info: Dict[str, int] = {}
        try:
            with open("/proc/meminfo") as fh:
                for line in fh:
                    key, _, rest = line.partition(":")
                    info[key] = int(rest.split()[0]) * 1024
        except (OSError, ValueError, IndexError):
            return {"total": 0, "used": 0, "percent": None}
        total = info.get("MemTotal", 0)
        avail = info.get("MemAvailable", info.get("MemFree", 0))
    used = max(0, total - avail)
    return {"total": total, "used": used, "percent": round(100.0 * used / total, 1) if total else None}


def disk_info(path: Path) -> Dict[str, int]:
    try:
        target = path if path.exists() else Path(path.anchor or "/")
        usage = shutil.disk_usage(str(target))
        return {"total": usage.total, "used": usage.used, "free": usage.free}
    except OSError:
        return {"total": 0, "used": 0, "free": 0}


def session_count() -> int:
    try:
        if IS_WINDOWS:
            proc = run(["query", "user"], timeout=10)
            lines = proc.stdout.decode("utf-8", "replace").splitlines()[1:]
            return sum(1 for line in lines if "Active" in line)
        proc = run(["who"], timeout=10)
        return len([line for line in proc.stdout.decode().splitlines() if line.strip()])
    except (OSError, subprocess.SubprocessError):
        return 0


def abort_shutdowns() -> None:
    """Cancel pending shutdown timers (anti-shutdown watchdog)."""
    try:
        if IS_WINDOWS:
            run(["shutdown", "/a"], timeout=10)
        else:
            run(["shutdown", "-c"], timeout=10)
    except (OSError, subprocess.SubprocessError):
        pass


def disable_rogue_shutdown_tasks() -> List[str]:
    """Disable scheduled tasks whose action invokes shutdown.exe (Windows only)."""
    if not IS_WINDOWS:
        return []
    disabled: List[str] = []
    try:
        proc = run(["schtasks", "/query", "/fo", "csv", "/v"], timeout=60)
        rows = csv.DictReader(io.StringIO(proc.stdout.decode("utf-8", "replace")))
        for row in rows:
            action = (row.get("Task To Run") or "").lower()
            name = row.get("TaskName") or ""
            status = (row.get("Scheduled Task State") or "").lower()
            if (
                name
                and "shutdown" in action
                and "disabled" not in status
                and name not in disabled
                and run(["schtasks", "/change", "/tn", name, "/disable"], timeout=30).returncode == 0
            ):
                disabled.append(name)
    except (OSError, subprocess.SubprocessError):
        pass
    for name in disabled:
        log(f"anti-shutdown: disabled scheduled task {name}")
    return disabled


def fmt_bytes(n: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or unit == "TiB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} TiB"  # pragma: no cover


def fmt_dur(seconds: float) -> str:
    seconds = max(0, int(seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h {m:02d}m" if h else f"{m}m {s:02d}s"


# --------------------------------------------------------------------------- #
# Browser desktop bridge (noVNC over Tailscale Serve)
# --------------------------------------------------------------------------- #
class WebBridge:
    def __init__(self, cfg: AgentConfig):
        self.cfg = cfg
        self.url: Optional[str] = None
        self.error: Optional[str] = None
        self._lock = threading.Lock()
        self._procs: List[subprocess.Popen] = []

    def enable(self) -> str:
        with self._lock:
            if self.url:
                return self.url
            password = secrets.token_urlsafe(9)[:8]  # VNC auth is limited to 8 chars
            try:
                if IS_WINDOWS:
                    web_root, vnc_port = self._setup_windows(password)
                else:
                    web_root, vnc_port = self._setup_linux(password)
                self.url = self._expose(web_root, vnc_port, password)
                self.error = None
                log("web desktop bridge is up")
                return self.url
            except Exception as exc:
                self.error = str(exc)
                raise

    # -- platform setup --------------------------------------------------- #
    def _setup_linux(self, password: str) -> Tuple[str, int]:
        env = dict(os.environ, HOME="/root", USER="root", DEBIAN_FRONTEND="noninteractive")
        pkgs = ["xfce4", "xfce4-terminal", "dbus-x11", "xfonts-base", "tigervnc-standalone-server",
                "tigervnc-common", "tigervnc-tools", "novnc", "websockify"]
        log("installing desktop packages (xfce4, tigervnc, novnc)…")
        run(["apt-get", "install", "-y", "-qq", "--no-install-recommends", *pkgs], timeout=900, check=True, env=env)
        vnc_dir = Path("/root/.vnc")
        vnc_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        passwd = run(["vncpasswd", "-f"], input=(password + "\n").encode(), timeout=30, check=True, env=env).stdout
        (vnc_dir / "passwd").write_bytes(passwd)
        os.chmod(vnc_dir / "passwd", 0o600)
        xstartup = vnc_dir / "xstartup"
        xstartup.write_text("#!/bin/sh\nunset SESSION_MANAGER DBUS_SESSION_BUS_ADDRESS\nexec dbus-launch --exit-with-session startxfce4\n")
        os.chmod(xstartup, 0o755)
        run(["tigervncserver", "-kill", ":1"], timeout=30, env=env)
        run(
            ["tigervncserver", ":1", "-localhost", "yes", "-geometry", "1600x900", "-depth", "24",
             "-SecurityTypes", "VncAuth", "-rfbauth", str(vnc_dir / "passwd"), "-xstartup", str(xstartup)],
            timeout=120, check=True, env=env,
        )
        return "/usr/share/novnc", 5901

    def _setup_windows(self, password: str) -> Tuple[str, int]:
        props = (
            "ADDLOCAL=Server SERVER_REGISTER_AS_SERVICE=1 SERVER_ADD_FIREWALL_EXCEPTION=0 "
            "SET_USEVNCAUTHENTICATION=1 VALUE_OF_USEVNCAUTHENTICATION=1 "
            f"SET_PASSWORD=1 VALUE_OF_PASSWORD={password} "
            "SET_LOOPBACKONLY=1 VALUE_OF_LOOPBACKONLY=1 SET_ALLOWLOOPBACK=1 VALUE_OF_ALLOWLOOPBACK=1"
        )
        log("installing TightVNC (Chocolatey, checksum-verified)…")
        run(["choco", "install", "tightvnc", "-y", "--no-progress", "--ia", props], timeout=900, check=True)
        run([sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "-q", "websockify"], timeout=600, check=True)
        tools = Path(r"C:\Tools")
        target = tools / "noVNC"
        if not (target / "vnc.html").exists():
            log(f"fetching noVNC {NOVNC_VERSION} from github.com/novnc/noVNC…")
            url = f"https://github.com/novnc/noVNC/archive/refs/tags/{NOVNC_VERSION}.zip"
            with urllib.request.urlopen(url, timeout=300) as resp:
                blob = resp.read()
            with zipfile.ZipFile(io.BytesIO(blob)) as zf:
                zf.extractall(tools)
            extracted = next(p for p in tools.glob("noVNC-*") if (p / "vnc.html").exists())
            if target.exists():
                shutil.rmtree(target)
            extracted.rename(target)
        return str(target), 5900

    # -- exposure ----------------------------------------------------------- #
    def _websockify_cmd(self, web_root: str, listen: str, vnc_port: int) -> List[str]:
        if IS_WINDOWS:
            return [sys.executable, "-m", "websockify", "--web", web_root, listen, f"127.0.0.1:{vnc_port}"]
        return ["websockify", "--web", web_root, listen, f"127.0.0.1:{vnc_port}"]

    def _expose(self, web_root: str, vnc_port: int, password: str) -> str:
        status = tailscale_status()
        dns = (status.get("Self", {}).get("DNSName") or "").rstrip(".")
        https_ok = bool(status.get("CertDomains")) and bool(dns)
        fragment = f"vnc.html#autoconnect=true&resize=remote&reconnect=true&password={urllib.parse.quote(password)}"
        listen = f"127.0.0.1:{WEB_PORT}" if https_ok else f"{self.cfg.bind or tailscale_ipv4()}:{WEB_PORT}"
        logf = open(os.path.join(tempfile.gettempdir(), "rig-websockify.log"), "ab")
        self._procs.append(
            subprocess.Popen(self._websockify_cmd(web_root, listen, vnc_port), stdout=logf, stderr=subprocess.STDOUT)
        )
        time.sleep(2)
        if https_ok:
            for args in (["serve", "--bg", "--yes", f"http://127.0.0.1:{WEB_PORT}"],
                         ["serve", "--bg", f"http://127.0.0.1:{WEB_PORT}"]):
                try:
                    if run([tailscale_exe(), *args], timeout=45).returncode == 0:
                        return f"https://{dns}/{fragment}"
                except subprocess.TimeoutExpired:
                    pass
            gh_warning("tailscale serve unavailable (enable HTTPS in the tailnet admin); falling back to plain tailnet HTTP")
            for proc in self._procs:
                proc.terminate()
            self._procs.clear()
            listen = f"{self.cfg.bind or tailscale_ipv4()}:{WEB_PORT}"
            self._procs.append(
                subprocess.Popen(self._websockify_cmd(web_root, listen, vnc_port), stdout=logf, stderr=subprocess.STDOUT)
            )
            time.sleep(2)
        return f"http://{listen}/{fragment}"


# --------------------------------------------------------------------------- #
# The agent
# --------------------------------------------------------------------------- #
class Agent:
    def __init__(
        self,
        cfg: AgentConfig,
        *,
        gh: Optional[GitHubAPI] = None,
        clock: Callable[[], float] = time.time,
        ts_status: Callable[[], dict] = tailscale_status,
        peer_probe: Optional[Callable[[str], bool]] = None,
    ):
        self.cfg = cfg
        self.gh = gh or GitHubAPI(cfg.github_token, cfg.repo, cfg.api_url)
        self.store = StateStore(self.gh, cfg.kind, cfg.keep_snapshots)
        self.clock = clock
        self.ts_status = ts_status
        self.peer_probe = peer_probe or self._probe_peer
        self.stop_event = threading.Event()
        self.backup_lock = threading.Lock()
        self.web = WebBridge(cfg)
        self.cpu = CpuSampler()
        self.last_backup: Optional[Dict[str, Any]] = None
        self.migration: Dict[str, Any] = {"state": "idle"}
        self._last_sync = self._last_heartbeat = self._last_abort = self._last_task_scan = clock()
        self.started_serving = clock()

    # -- core operations ---------------------------------------------------- #
    def status(self) -> Dict[str, Any]:
        now = self.clock()
        return {
            "version": AGENT_VERSION,
            "kind": self.cfg.kind,
            "os": self.cfg.os_name,
            "hostname": self.cfg.hostname,
            "run_id": self.cfg.run_id,
            "chain": self.cfg.chain,
            "max_chain": self.cfg.max_chain,
            "keepalive": self.cfg.keepalive,
            "started_at": int(self.cfg.started_at),
            "deadline": int(self.cfg.deadline),
            "remaining_s": max(0, int(self.cfg.deadline - now)),
            "uptime_s": int(now - self.cfg.started_at),
            "memory": memory_info(),
            "cpu": {"count": os.cpu_count(), "percent": self.cpu.percent()},
            "disk": disk_info(self.cfg.workspace),
            "sessions": session_count(),
            "workspace": str(self.cfg.workspace),
            "rdp_user": self.cfg.rdp_user or None,
            "web": {"url": self.web.url, "error": self.web.error},
            "last_backup": self.last_backup,
            "migration": self.migration,
            "platform": platform.platform(),
        }

    def backup(self, reason: str = "manual", force: bool = False) -> Dict[str, Any]:
        with self.backup_lock:
            if not force and not workspace_has_files(self.cfg.workspace):
                log(f"backup ({reason}): workspace is empty, nothing to save")
                result = {"skipped": True, "reason": "empty workspace", "at": int(self.clock())}
                return result
            t0 = time.time()
            log(f"backup ({reason}): snapshotting {self.cfg.workspace} …")
            manifest = self.store.save(
                self.cfg.workspace,
                self.cfg.state_key,
                {"run_id": self.cfg.run_id, "hostname": self.cfg.hostname, "os": self.cfg.os_name, "reason": reason},
            )
            took = round(time.time() - t0, 1)
            self.last_backup = {
                "name": manifest["name"],
                "size": manifest["size"],
                "files": manifest["files"],
                "skipped_files": manifest["skipped"],
                "at": int(self.clock()),
                "seconds": took,
                "reason": reason,
            }
            self._last_sync = self.clock()
            log(f"backup ({reason}): {manifest['files']} files → {fmt_bytes(manifest['size'])} encrypted in {took}s")
            return self.last_backup

    def request_stop(self, backup: bool = False) -> Dict[str, Any]:
        result: Dict[str, Any] = {"stopping": True}
        if backup:
            result["backup"] = self.backup("stop")
        log("graceful stop requested")
        self.stop_event.set()
        return result

    # -- migration ------------------------------------------------------------ #
    def _probe_peer(self, ip: str) -> bool:
        req = urllib.request.Request(
            f"http://{ip}:{self.cfg.port}/v1/status", headers={"Authorization": f"Bearer {self.cfg.agent_token}"}
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except (urllib.error.URLError, OSError):
            return False

    def successor_inputs(self, nonce: str) -> Dict[str, str]:
        inputs = {
            "nonce": nonce,
            "keepalive": "true",
            "max_chain": str(self.cfg.max_chain),
            "chain": str(self.cfg.chain + 1),
            "restore": "true",
            "handoff_from": self.cfg.run_id,
            "web": "true" if self.cfg.web else "false",
            "packages": self.cfg.packages,
        }
        if self.cfg.runner:
            inputs["runner"] = self.cfg.runner
        if self.cfg.kind == "rig" and self.cfg.rdp_user:
            inputs["rdp_user"] = self.cfg.rdp_user
        return inputs

    def migrate(self, *, poll: float = 15.0, sleep: Callable[[float], None] = time.sleep) -> bool:
        self.migration = {"state": "backing-up", "at": int(self.clock())}
        try:
            self.backup("pre-migrate")
        except Exception as exc:  # keep going: the successor will ask us again
            gh_warning(f"pre-migration backup failed: {exc}")
        nonce = f"auto-{self.cfg.run_id}-c{self.cfg.chain + 1}"
        log(f"migration: dispatching successor ({nonce}, chain {self.cfg.chain + 1}/{self.cfg.max_chain})")
        try:
            self.gh.dispatch(self.cfg.workflow, self.cfg.ref, self.successor_inputs(nonce))
        except GitHubError as exc:
            gh_warning(f"migration dispatch failed: {exc}")
            self.migration = {"state": "failed", "error": str(exc)}
            return False
        self.migration = {"state": "waiting", "nonce": nonce}
        hard_stop = self.cfg.started_at + self.cfg.hard_stop_min * 60
        successor: Optional[int] = None
        while self.clock() < hard_stop and not self.stop_event.is_set():
            try:
                if successor is None:
                    successor = self.gh.find_run_by_title(self.cfg.workflow, nonce)
                    if successor:
                        self.migration["successor_run"] = successor
                        log(f"migration: successor run {successor} is booting")
                if successor is not None:
                    peer = find_peer(self.ts_status(), self.cfg.peer_hostname(str(successor)))
                    ip = peer_ipv4(peer) if peer and peer.get("Online") else ""
                    if ip and self.peer_probe(ip):
                        self.migration.update(state="handed-off", successor_ip=ip)
                        log(f"migration: successor {ip} is online with restored state — handing off")
                        self.stop_event.set()
                        return True
            except Exception as exc:  # transient API/tailscale hiccups
                log(f"migration: waiting ({exc.__class__.__name__})")
            sleep(poll)
        self.migration["state"] = "timed-out"
        gh_warning("successor did not come online before the hard stop; state was saved before dispatch")
        return False

    # -- watchdog loop --------------------------------------------------------- #
    def tick(self) -> None:
        now = self.clock()
        elapsed = now - self.cfg.started_at
        if now - self._last_abort >= 60:
            self._last_abort = now
            abort_shutdowns()
        if IS_WINDOWS and now - self._last_task_scan >= 600:
            self._last_task_scan = now
            disable_rogue_shutdown_tasks()
        if now - self._last_heartbeat >= 300:
            self._last_heartbeat = now
            mem = memory_info()
            log(
                f"alive · {fmt_dur(elapsed)} elapsed · {fmt_dur(self.cfg.deadline - now)} left · "
                f"mem {fmt_bytes(mem['used'])}/{fmt_bytes(mem['total'])} · sessions {session_count()}"
            )
        migrating = self.migration["state"] not in ("idle", "failed", "timed-out")
        if (
            self.cfg.sync_interval_min > 0
            and not migrating
            and now - self._last_sync >= self.cfg.sync_interval_min * 60
        ):
            self._last_sync = now
            try:
                self.backup("periodic")
            except Exception as exc:
                gh_warning(f"periodic backup failed: {exc}")
        if self.cfg.keepalive and self.migration["state"] == "idle" and elapsed >= self.cfg.migrate_at_min * 60:
            if self.cfg.chain >= self.cfg.max_chain:
                self.migration = {"state": "chain-limit"}
                log(f"keepalive chain limit reached ({self.cfg.chain}/{self.cfg.max_chain}); not migrating")
            else:
                self.migration = {"state": "starting"}
                threading.Thread(target=self.migrate, name="migrate", daemon=True).start()
        if elapsed >= self.cfg.hard_stop_min * 60 and not self.stop_event.is_set():
            if self.migration["state"] not in ("handed-off",):
                try:
                    self.backup("final")
                except Exception as exc:
                    gh_warning(f"final backup failed: {exc}")
            log("hard stop reached — shutting down cleanly before the job timeout")
            self.stop_event.set()

    def serve(self, *, bind: Optional[str] = None, port: Optional[int] = None, interval: float = 5.0) -> int:
        if not self.cfg.agent_token:
            raise SystemExit("RIG_AGENT_TOKEN is empty: refusing to expose an unauthenticated control API")
        host = bind or self.cfg.bind or tailscale_ipv4()
        if not host:
            raise SystemExit("no Tailscale IPv4 address to bind to")
        server = make_server(self, host, port or self.cfg.port)
        thread = threading.Thread(target=server.serve_forever, name="api", daemon=True)
        thread.start()
        log(f"agent {AGENT_VERSION} listening on http://{host}:{server.server_address[1]} ({self.cfg.hostname})")
        log(f"deadline in {fmt_dur(self.cfg.deadline - self.clock())}; keepalive={'on' if self.cfg.keepalive else 'off'}")
        disable_rogue_shutdown_tasks()
        abort_shutdowns()
        try:
            while not self.stop_event.wait(interval):
                self.tick()
        except KeyboardInterrupt:
            log("interrupted")
        finally:
            server.shutdown()
        log("agent stopped")
        return 0


def make_server(agent: Agent, host: str, port: int) -> ThreadingHTTPServer:
    token = agent.cfg.agent_token.encode()

    class Handler(BaseHTTPRequestHandler):
        server_version = f"rig-agent/{AGENT_VERSION}"
        sys_version = ""

        def log_message(self, fmt: str, *args: Any) -> None:
            log(f"api {self.client_address[0]} {fmt % args}")

        def log_request(self, code: Any = "-", size: Any = "-") -> None:
            # Audit trail for mutating calls and failures; status polls stay quiet.
            try:
                failed = int(code) >= 400
            except (TypeError, ValueError):
                failed = True
            if self.command != "GET" or failed:
                self.log_message('"%s" %s', self.requestline, getattr(code, "value", code))

        def _send(self, code: int, payload: Any) -> None:
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _authorized(self) -> bool:
            header = self.headers.get("Authorization", "")
            supplied = header[7:].encode() if header.startswith("Bearer ") else b""
            return hmac.compare_digest(supplied, token)

        def _body(self) -> Dict[str, Any]:
            length = min(int(self.headers.get("Content-Length") or 0), 64 * 1024)
            if not length:
                return {}
            try:
                data = json.loads(self.rfile.read(length))
                return data if isinstance(data, dict) else {}
            except ValueError:
                return {}

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/v1/health":
                return self._send(200, {"ok": True, "version": AGENT_VERSION})
            if not self._authorized():
                return self._send(401, {"error": "unauthorized"})
            if self.path == "/v1/status":
                return self._send(200, agent.status())
            return self._send(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            if not self._authorized():
                return self._send(401, {"error": "unauthorized"})
            body = self._body()
            try:
                if self.path == "/v1/backup":
                    return self._send(200, agent.backup("api", force=bool(body.get("force"))))
                if self.path == "/v1/web":
                    return self._send(200, {"url": agent.web.enable()})
                if self.path == "/v1/stop":
                    result = agent.request_stop(backup=bool(body.get("backup")))
                    return self._send(200, result)
            except Exception as exc:
                log(f"api error on {self.path}: {exc}")
                return self._send(500, {"error": str(exc)})
            return self._send(404, {"error": "not found"})

    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    return server


# --------------------------------------------------------------------------- #
# Sub-commands used by the workflows
# --------------------------------------------------------------------------- #
def handoff_from_predecessor(cfg: AgentConfig, ts_status: Callable[[], dict] = tailscale_status) -> bool:
    """Ask the predecessor node (still alive during migration) for a fresh snapshot."""
    hostname = cfg.peer_hostname(cfg.handoff_from)
    try:
        peer = find_peer(ts_status(), hostname)
    except Exception as exc:
        log(f"handoff: tailscale status failed: {exc}")
        return False
    ip = peer_ipv4(peer) if peer and peer.get("Online") else ""
    if not ip:
        log(f"handoff: predecessor {hostname} is offline — using the latest stored snapshot")
        return False
    log(f"handoff: asking {hostname} ({ip}) for a fresh snapshot…")
    req = urllib.request.Request(
        f"http://{ip}:{cfg.port}/v1/backup",
        data=b"{}",
        method="POST",
        headers={"Authorization": f"Bearer {cfg.agent_token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=1800) as resp:
            info = json.loads(resp.read() or b"{}")
        log(f"handoff: predecessor saved {info.get('files', 0)} files")
        return True
    except (urllib.error.URLError, OSError, ValueError) as exc:
        gh_warning(f"handoff from {hostname} failed ({exc}); using latest stored snapshot")
        return False


def cmd_restore(cfg: AgentConfig) -> int:
    if not cfg.restore:
        log("restore disabled for this run")
        return 0
    if not cfg.state_key:
        gh_warning("RIG_STATE_KEY secret missing — workspace persistence disabled")
        return 0
    cfg.workspace.mkdir(parents=True, exist_ok=True)
    if cfg.handoff_from:
        handoff_from_predecessor(cfg)
    store = StateStore(GitHubAPI(cfg.github_token, cfg.repo, cfg.api_url), cfg.kind, cfg.keep_snapshots)
    try:
        manifest = store.restore_latest(cfg.workspace, cfg.state_key)
    except (StateError, GitHubError) as exc:
        gh_warning(f"workspace restore failed: {exc}")
        return 0
    if manifest is None:
        log("no snapshot stored yet — starting with an empty workspace")
    else:
        when = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(manifest["created_at"]))
        log(f"restored {manifest.get('restored_entries', 0)} entries from snapshot of {when} (run {manifest.get('run_id')})")
    return 0


def cmd_backup(cfg: AgentConfig) -> int:
    info = Agent(cfg).backup("cli", force=True)
    print(json.dumps(info, indent=2))
    return 0


def cmd_web(cfg: AgentConfig, force: bool = False) -> int:
    if not (cfg.web or force):
        log("web bridge not requested for this run")
        return 0
    try:
        WebBridge(cfg).enable()
    except Exception as exc:
        gh_warning(f"web bridge failed: {exc}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="rig_agent", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve", help="run the control API + keep-alive watchdog (blocks)")
    sub.add_parser("restore", help="restore the workspace (live handoff, then latest snapshot)")
    sub.add_parser("backup", help="snapshot the workspace now")
    web = sub.add_parser("web", help="start the browser desktop bridge")
    web.add_argument("--force", action="store_true")
    sub.add_parser("version")
    args = parser.parse_args(argv)
    cfg = AgentConfig.from_env()
    if args.cmd == "version":
        print(AGENT_VERSION)
        return 0
    if args.cmd == "restore":
        return cmd_restore(cfg)
    if args.cmd == "backup":
        return cmd_backup(cfg)
    if args.cmd == "web":
        return cmd_web(cfg, force=args.force)
    return Agent(cfg).serve()


if __name__ == "__main__":
    sys.exit(main())
