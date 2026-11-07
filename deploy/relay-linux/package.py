#!/usr/bin/env python3
"""Package already-built relay binaries and the pinned upstream Caddy (stdlib only)."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile
import tomllib


ROOT = Path(__file__).absolute().parents[2]
CADDY_VERSION = "2.11.7"
CADDY_SHA256 = "678ade3bfc088749c81a681adc603333ee0bb023b6a6cfe3c0f58bef8ff854e9"
CADDY_URL = "https://github.com/caddyserver/caddy/releases/download/v2.11.7/caddy_2.11.7_linux_amd64.tar.gz"
PREFIX = "koto-relay-linux-x64"


def regular_file(path):
    if any(p.is_symlink() for p in (path, *path.parents)) or not path.is_file():
        raise ValueError(f"Expected a regular file without symlinks: {path}")
    return path.read_bytes()


def validate_elf(data, name, static=False):
    if (len(data) < 64 or data[:6] != b"\x7fELF\x02\x01" or
            struct.unpack_from("<H", data, 18)[0] != 62 or
            struct.unpack_from("<H", data, 16)[0] not in (2, 3)):
        raise ValueError(f"Expected Linux ELF64 x86_64 executable: {name}")
    if static:
        offset = struct.unpack_from("<Q", data, 32)[0]
        size, count = struct.unpack_from("<HH", data, 54)
        if size < 56 or count > 128 or offset + size * count > len(data):
            raise ValueError(f"Invalid ELF program headers: {name}")
        if any(struct.unpack_from("<I", data, offset + size * i)[0] == 3 for i in range(count)):
            raise ValueError(f"Expected static Caddy without an ELF interpreter: {name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--caddy-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        raise ValueError(f"Refusing to overwrite: {output}")
    if any(p.is_symlink() for p in output.parents) or not output.parent.is_dir():
        raise ValueError("Output directory must exist and must not contain symlinks.")
    caddy = args.caddy_dir.absolute()
    caddy_data = regular_file(caddy / "caddy")
    if hashlib.sha256(caddy_data).hexdigest() != CADDY_SHA256:
        raise ValueError("Caddy binary does not match the verified 2.11.7 Linux amd64 binary.")
    # No supplied program is executed; ELF validation happens only after pinning Caddy.
    binaries = {
        "messenger-relay": regular_file(ROOT / "target/release/messenger-relay"),
        "queue_ticket": regular_file(ROOT / "target/release/examples/queue_ticket"),
        "caddy": caddy_data,
    }
    for name, data in binaries.items():
        validate_elf(data, name, static=name == "caddy")
    git = lambda *cmd: subprocess.check_output(["git", "-C", str(ROOT), *cmd], text=True).strip()
    commit = git("rev-parse", "HEAD")
    source_clean = not git("status", "--porcelain", "--untracked-files=all")
    files = {f"bin/{name}": (data, 0o755) for name, data in binaries.items()}
    for relative in (
        "install.sh", "issue-ticket.sh", "Caddyfile.template", "smoke.py",
        "systemd/kotopizdelka-relay.service", "systemd/kotopizdelka-relay-proxy.service",
    ):
        mode = 0o755 if relative.endswith((".sh", ".py")) else 0o644
        files[relative] = (regular_file(ROOT / "deploy/relay-linux" / relative), mode)
    for path in sorted((ROOT / "docs").glob("*.md")):
        files[f"docs/{path.name}"] = (regular_file(path), 0o644)
    for name in ("LICENSE", "README.md"):
        files[f"licenses/caddy/{name}"] = (regular_file(caddy / name), 0o644)
    info = {
        "relay_version": tomllib.loads(regular_file(ROOT / "crates/relay/Cargo.toml").decode())["package"]["version"],
        "source_commit": commit,
        "source_working_tree_clean": source_clean,
        "architecture": "Linux x86_64; Ubuntu 24.04 deployment",
        "relay_build": "cargo build -p messenger-relay --release --locked --offline",
        "ticket_build": "cargo build -p messenger-relay --example queue_ticket --release --locked --offline",
        "cargo_lock_sha256": hashlib.sha256(regular_file(ROOT / "Cargo.lock")).hexdigest(),
        "binary_sha256": {name: hashlib.sha256(data).hexdigest() for name, data in binaries.items()},
        "caddy": {"version": CADDY_VERSION, "source_url": CADDY_URL, "binary_sha256": CADDY_SHA256},
        "validation_limit": "Release binaries compiled; native VPS service isolation, DNS, ACME certificate and public delivery still require verification.",
    }
    files["BUILD_INFO.json"] = ((json.dumps(info, ensure_ascii=False, indent=2) + "\n").encode(), 0o644)
    readme = """KotoPizdelka relay for Ubuntu 24.04 x86_64

This package contains native relay programs and an upstream Caddy build.
Use your own hostname and public IPv4; configure DNS and review port usage first.
From the extracted package directory:
  sha256sum --check SHA256SUMS
  bash ./install.sh --check YOUR_HOSTNAME YOUR_IPV4
  sudo bash ./install.sh --install YOUR_HOSTNAME YOUR_IPV4

The installer targets a fresh server. Read docs/RELAY_DEPLOYMENT.md first.
Do not publish issued tickets, relay.env or backup archives.
BUILD_INFO.json records the build inputs and validation limits.
"""
    files["README.txt"] = (readme.encode(), 0o644)
    sums = "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, (data, _) in sorted(files.items()))
    files["SHA256SUMS"] = (sums.encode("ascii"), 0o644)
    with tempfile.TemporaryDirectory(prefix="koto-relay-package-", dir="/tmp") as temporary:
        staging = Path(temporary) / PREFIX
        for name, (data, mode) in files.items():
            path = staging / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(mode)
        raw = output.open("xb")
        try:
            with raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w") as archive:
                    for path in [staging, *sorted(staging.rglob("*"))]:
                        item = archive.gettarinfo(str(path), str(path.relative_to(staging.parent)))
                        item.uid = item.gid = item.mtime = 0
                        item.uname = item.gname = "root"
                        item.mode = 0o755 if path.is_dir() else files[str(path.relative_to(staging))][1]
                        if path.is_file():
                            with path.open("rb") as stream:
                                archive.addfile(item, stream)
                        else:
                            archive.addfile(item)
        except Exception:
            output.unlink(missing_ok=True)
            raise
    print(f"Created {output} ({output.stat().st_size} bytes); source commit {commit}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"ERROR: {error}")
