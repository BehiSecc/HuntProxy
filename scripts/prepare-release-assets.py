#!/usr/bin/env python3
"""Build deterministic embedded runtime and first-party plugin release assets."""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile
import tempfile
import urllib.request


PLAYWRIGHT_VERSION = "1.64.0"
NODE_VERSION = "22.23.2"
PUBLISHED_PLUGIN_COMMIT = "95ad5b29cb02e8b1aa1c0ec0b6d7cb1e485f0c32"
NODE_CHECKSUMS_URL = f"https://nodejs.org/dist/v{NODE_VERSION}/SHASUMS256.txt"
NODE_ASSETS = (
    "node-v22.23.2-linux-x64.tar.gz",
    "node-v22.23.2-linux-arm64.tar.gz",
    "node-v22.23.2-darwin-x64.tar.gz",
    "node-v22.23.2-darwin-arm64.tar.gz",
)
EXCLUDED_PACKAGE_FILES = {"aws-credentials.toml", ".env"}
MAX_PLUGIN_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_PLUGIN_EXPANDED_BYTES = 64 * 1024 * 1024


def run(repo: Path, *args: str, text: bool = False) -> bytes | str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=text,
    )
    return result.stdout


def resolve_commit(repo: Path, revision: str) -> str:
    value = str(run(repo, "rev-parse", f"{revision}^{{commit}}", text=True)).strip()
    if len(value) != 40 or any(ch not in "0123456789abcdef" for ch in value):
        raise ValueError(f"invalid git commit: {revision}")
    return value


def git_file(repo: Path, commit: str, path: str) -> bytes:
    return bytes(run(repo, "show", f"{commit}:{path}"))


def package_files(repo: Path, commit: str) -> dict[str, dict[str, bytes]]:
    encoded = bytes(run(repo, "ls-tree", "-r", "-z", commit, "--", "plugins"))
    packages: dict[str, dict[str, bytes]] = {}
    for record in encoded.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, object_type, _ = metadata.decode("ascii").split(" ", 2)
        path = raw_path.decode("utf-8")
        relative = PurePosixPath(path)
        if (
            object_type != "blob"
            or mode not in {"100644", "100755"}
            or relative.is_absolute()
            or ".." in relative.parts
            or len(relative.parts) < 3
            or relative.parts[0] != "plugins"
        ):
            raise ValueError(f"unsafe or unsupported plugin entry at {commit}: {path}")
        name = relative.parts[1]
        package_path = PurePosixPath(*relative.parts[2:]).as_posix()
        if PurePosixPath(package_path).name in EXCLUDED_PACKAGE_FILES:
            continue
        packages.setdefault(name, {})[package_path] = git_file(repo, commit, path)
    packages = {
        name: files
        for name, files in packages.items()
        if "plugin.json" in files and "index.js" in files
    }
    if not packages:
        raise ValueError(f"no plugin packages found at {commit}")
    return dict(sorted(packages.items()))


def fingerprint(packages: dict[str, dict[str, bytes]]) -> dict[str, dict[str, str]]:
    return {
        name: {
            path: hashlib.sha256(content).hexdigest()
            for path, content in sorted(files.items())
        }
        for name, files in sorted(packages.items())
    }


def tar_bytes(
    repo: Path,
    current_commit: str,
    current: dict[str, dict[str, bytes]],
    catalog: dict[str, object],
) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        entries: list[tuple[str, bytes, int]] = [
            (
                "catalog.json",
                (json.dumps(catalog, sort_keys=True, separators=(",", ":")) + "\n").encode(),
                0o644,
            )
        ]
        for root_file in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
            try:
                entries.append((root_file, git_file(repo, current_commit, root_file), 0o644))
            except subprocess.CalledProcessError:
                pass
        for package, files in current.items():
            for path, content in files.items():
                entries.append((f"plugins/{package}/{path}", content, 0o644))
        for name, content, mode in sorted(entries):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = mode
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, io.BytesIO(content))
    return output.getvalue()


def verify_playwright(tgz: Path, lock: Path) -> tuple[str, str, str]:
    lock_data = json.loads(lock.read_text(encoding="utf-8"))
    package = lock_data["packages"]["node_modules/playwright-core"]
    if package["version"] != PLAYWRIGHT_VERSION:
        raise ValueError(f"package-lock does not pin playwright-core {PLAYWRIGHT_VERSION}")
    algorithm, encoded = package["integrity"].split("-", 1)
    if algorithm != "sha512":
        raise ValueError("playwright-core lock integrity must use SHA-512")
    actual = hashlib.sha512(tgz.read_bytes()).digest()
    if actual != base64.b64decode(encoded, validate=True):
        raise ValueError("playwright-core archive does not match package-lock integrity")
    with tarfile.open(tgz, mode="r:gz") as archive:
        metadata_entry = archive.getmember("package/browsers.json")
        if metadata_entry.size > 64 * 1024:
            raise ValueError("playwright-core browser metadata is unexpectedly large")
        metadata_file = archive.extractfile(metadata_entry)
        if metadata_file is None:
            raise ValueError("playwright-core archive is missing browser metadata")
        metadata = json.load(metadata_file)
    chromium = [
        browser
        for browser in metadata.get("browsers", [])
        if browser.get("name") == "chromium" and browser.get("installByDefault") is True
    ]
    if len(chromium) != 1:
        raise ValueError("playwright-core archive has invalid Chromium metadata")
    revision = str(chromium[0].get("revision", ""))
    browser_version = str(chromium[0].get("browserVersion", ""))
    if not revision.isdecimal() or not browser_version:
        raise ValueError("playwright-core archive has incomplete Chromium metadata")
    return hashlib.sha512(tgz.read_bytes()).hexdigest(), revision, browser_version


def node_manifest(checksums_path: Path | None) -> dict[str, object]:
    if checksums_path is None:
        with urllib.request.urlopen(NODE_CHECKSUMS_URL, timeout=30) as response:
            encoded = response.read(1024 * 1024 + 1)
        if len(encoded) > 1024 * 1024:
            raise ValueError("Node.js checksum file is unexpectedly large")
        text = encoded.decode("utf-8")
    else:
        text = checksums_path.read_text(encoding="utf-8")
    found: dict[str, str] = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1].lstrip("*") in NODE_ASSETS:
            found[fields[1].lstrip("*")] = fields[0].lower()
    if set(found) != set(NODE_ASSETS) or any(
        len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value)
        for value in found.values()
    ):
        raise ValueError("upstream Node.js checksums are incomplete")
    platforms = {}
    for os_name, arch, asset in (
        ("linux", "x86_64", NODE_ASSETS[0]),
        ("linux", "aarch64", NODE_ASSETS[1]),
        ("macos", "x86_64", NODE_ASSETS[2]),
        ("macos", "aarch64", NODE_ASSETS[3]),
    ):
        platforms[f"{os_name}-{arch}"] = {
            "asset": asset,
            "sha256": found[asset],
        }
    return {
        "schema_version": 1,
        "version": NODE_VERSION,
        "source": f"https://nodejs.org/dist/v{NODE_VERSION}",
        "checksums_source": NODE_CHECKSUMS_URL,
        "platforms": platforms,
    }


def atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_bytes(content)
    os.replace(temporary, path)


def asset_payload(path: Path) -> bytes:
    if path.name != "plugins-catalog.tar.zst":
        return path.read_bytes()
    if path.stat().st_size > MAX_PLUGIN_ARCHIVE_BYTES:
        raise SystemExit(f"release asset exceeds the encoded size limit: {path.name}")
    # Zstd versions can encode the same tar differently. Verify the exact tar,
    # including its catalog fingerprints and metadata, instead of encoder bytes.
    with subprocess.Popen(
        ["zstd", "-q", "-d", "-c", str(path)], stdout=subprocess.PIPE
    ) as decoder:
        assert decoder.stdout is not None
        content = decoder.stdout.read(MAX_PLUGIN_EXPANDED_BYTES + 1)
        if len(content) > MAX_PLUGIN_EXPANDED_BYTES:
            decoder.kill()
            decoder.wait()
            raise SystemExit(f"release asset expands beyond the size limit: {path.name}")
        if decoder.wait() != 0:
            raise SystemExit(f"release asset cannot be decoded: {path.name}")
    return content


def verify_asset(existing: Path, candidate: Path) -> None:
    if asset_payload(existing) != asset_payload(candidate):
        raise SystemExit(f"release asset differs from generated output: {existing.name}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("plugin_repo", type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path("resources/release"))
    parser.add_argument("--current-commit", default="HEAD")
    parser.add_argument("--prior-commit", default=PUBLISHED_PLUGIN_COMMIT)
    parser.add_argument("--playwright-tgz", type=Path, required=True)
    parser.add_argument("--playwright-lock", type=Path)
    parser.add_argument("--node-checksums", type=Path)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify existing output assets without rewriting them",
    )
    args = parser.parse_args()

    if args.check:
        temporary_root = os.environ.get("TMPDIR")
        with tempfile.TemporaryDirectory(
            prefix="huntproxy-release-check-", dir=temporary_root
        ) as temporary:
            generated = Path(temporary) / "release"
            command = [
                sys.executable,
                str(Path(__file__).resolve()),
                str(args.plugin_repo),
                "--output-dir",
                str(generated),
                "--current-commit",
                args.current_commit,
                "--prior-commit",
                args.prior_commit,
                "--playwright-tgz",
                str(args.playwright_tgz),
            ]
            if args.playwright_lock is not None:
                command.extend(["--playwright-lock", str(args.playwright_lock)])
            if args.node_checksums is not None:
                command.extend(["--node-checksums", str(args.node_checksums)])
            subprocess.run(command, check=True, stdout=subprocess.DEVNULL)
            expected_names = {
                "plugins-catalog.tar.zst",
                f"playwright-core-{PLAYWRIGHT_VERSION}.tgz",
                "playwright-core.json",
                "node-runtimes.json",
            }
            actual_names = {
                path.name for path in args.output_dir.iterdir() if path.is_file()
            }
            if actual_names != expected_names:
                raise SystemExit("release asset set does not match generated output")
            for name in sorted(expected_names):
                existing = args.output_dir / name
                candidate = generated / name
                verify_asset(existing, candidate)
        print(f"verified release assets in {args.output_dir.resolve()}")
        return

    repo = args.plugin_repo.resolve()
    if str(run(repo, "status", "--porcelain", text=True)).strip():
        raise SystemExit("plugin repository must be clean")
    current_commit = resolve_commit(repo, args.current_commit)
    prior_commit = resolve_commit(repo, args.prior_commit)
    current = package_files(repo, current_commit)
    prior = package_files(repo, prior_commit)
    catalog: dict[str, object] = {
        "schema_version": 1,
        "current_commit": current_commit,
        "snapshots": [
            {"commit": current_commit, "packages": fingerprint(current)},
            {"commit": prior_commit, "packages": fingerprint(prior)},
        ],
    }
    catalog_tar = tar_bytes(repo, current_commit, current, catalog)

    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        prefix="huntproxy-plugins-", suffix=".tar", dir=output, delete=False
    ) as temp:
        temp.write(catalog_tar)
        tar_path = Path(temp.name)
    compressed_path = output / "plugins-catalog.tar.zst"
    compressed_temp = compressed_path.with_name(f".{compressed_path.name}.{os.getpid()}.tmp")
    try:
        subprocess.run(
            ["zstd", "-q", "-19", "-T1", "-f", str(tar_path), "-o", str(compressed_temp)],
            check=True,
        )
        os.replace(compressed_temp, compressed_path)
    finally:
        tar_path.unlink(missing_ok=True)
        compressed_temp.unlink(missing_ok=True)

    playwright_lock = args.playwright_lock
    if playwright_lock is None:
        playwright_lock = args.playwright_tgz.parent / "pinned-worker" / "package-lock.json"
    playwright_sha512, chromium_revision, chromium_version = verify_playwright(
        args.playwright_tgz, playwright_lock
    )
    atomic_write(output / f"playwright-core-{PLAYWRIGHT_VERSION}.tgz", args.playwright_tgz.read_bytes())
    atomic_write(
        output / "playwright-core.json",
        (
            json.dumps(
                {
                    "schema_version": 1,
                    "version": PLAYWRIGHT_VERSION,
                    "sha512": playwright_sha512,
                    "chromium_revision": chromium_revision,
                    "chromium_version": chromium_version,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode(),
    )
    atomic_write(
        output / "node-runtimes.json",
        (json.dumps(node_manifest(args.node_checksums), sort_keys=True, separators=(",", ":")) + "\n").encode(),
    )
    print(f"plugins {current_commit} (trusted prior {prior_commit})")
    print(
        f"playwright-core {PLAYWRIGHT_VERSION} sha512 {playwright_sha512}; "
        f"Chromium {chromium_version} revision {chromium_revision}"
    )
    print(f"wrote release assets to {output}")


if __name__ == "__main__":
    main()
