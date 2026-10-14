#!/usr/bin/env python3
"""Generate deterministic notices for the locked production Rust graph."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path


TARGETS = (
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
)
LICENSE_NAME = re.compile(
    r"^(?:(?:un)?licen[sc]es?|copying|notices?|copyrights?)(?:[._-].*)?$",
    re.IGNORECASE,
)
SPDX_WORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]*")
SPDX_OPERATORS = {"AND", "OR", "WITH"}
KNOWN_LICENSE_IDS = {
    "0BSD",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSL-1.0",
    "CDLA-Permissive-2.0",
    "ISC",
    "LLVM-exception",
    "MIT",
    "MPL-2.0",
    "Unicode-3.0",
    "Unlicense",
    "Zlib",
}
MAX_NOTICE_BYTES = 900_000

# A few upstream .crate archives omit the workspace-level license files. Each
# entry is exact-versioned so a dependency update fails closed until reviewed.
LICENSE_DONORS = {
    ("alloc-stdlib", "0.2.4"): (("alloc-no-stdlib", "2.0.4", "LICENSE"),),
    ("asn1-rs-impl", "0.2.0"): (
        ("asn1-rs", "0.6.2", "LICENSE-APACHE"),
        ("asn1-rs", "0.6.2", "LICENSE-MIT"),
    ),
    ("rquickjs-core", "0.12.2"): (("rquickjs", "0.12.2", "LICENSE"),),
}

# yasna 0.5.2 was published before its upstream repository started including
# these files in the .crate archive. The text is from upstream commit b7e65f9.
YASNA_MIT = """Copyright (c) 2016 Masaki Hara

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


def cargo_metadata(repo: Path, target: str) -> dict:
    command = [
        "cargo",
        "metadata",
        "--locked",
        "--format-version",
        "1",
        "--filter-platform",
        target,
    ]
    result = subprocess.run(
        command,
        cwd=repo,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    return json.loads(result.stdout)


def production_packages(repo: Path) -> list[dict]:
    packages: dict[str, dict] = {}
    reachable: set[str] = set()
    for target in TARGETS:
        metadata = cargo_metadata(repo, target)
        packages.update({package["id"]: package for package in metadata["packages"]})
        nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
        pending = [metadata["resolve"]["root"]]
        target_reachable: set[str] = set()
        while pending:
            package_id = pending.pop()
            if package_id in target_reachable:
                continue
            target_reachable.add(package_id)
            for dependency in nodes[package_id]["deps"]:
                if any(kind["kind"] != "dev" for kind in dependency["dep_kinds"]):
                    pending.append(dependency["pkg"])
        reachable.update(target_reachable)

    result = [packages[package_id] for package_id in reachable]
    return sorted(result, key=lambda package: (package["name"], package["version"]))


def validate_license_expression(package: dict) -> None:
    expression = package.get("license")
    if not expression:
        raise RuntimeError(
            f"{package['name']} {package['version']} has no declared license expression"
        )
    identifiers = {
        word
        for word in SPDX_WORD.findall(expression)
        if word.upper() not in SPDX_OPERATORS
    }
    unknown = identifiers - KNOWN_LICENSE_IDS
    if unknown:
        raise RuntimeError(
            f"{package['name']} {package['version']} has unreviewed license identifiers: "
            + ", ".join(sorted(unknown))
        )


def license_files(root: Path) -> list[Path]:
    files = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if LICENSE_NAME.fullmatch(path.name) or any(
            parent.name.lower() in {"license", "licenses", "licence", "licences"}
            for parent in path.parents
        ):
            files.append(path)
    return sorted(files, key=lambda path: path.relative_to(root).as_posix())


def read_notice(path: Path) -> str:
    data = path.read_bytes()
    if not data or b"\0" in data:
        raise RuntimeError(f"license/notice file is empty or non-text: {path}")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RuntimeError(f"license/notice file is not UTF-8: {path}") from error
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(line.rstrip() for line in normalized.split("\n")).rstrip() + "\n"


def locked_checksums(repo: Path) -> dict[tuple[str, str, str], str]:
    text = (repo / "Cargo.lock").read_text(encoding="utf-8")
    if not re.search(r"(?m)^version = 4$", text):
        raise RuntimeError("Cargo.lock must use the reviewed version 4 format")
    fields = {"name", "version", "source", "checksum"}
    packages = []
    current = None
    for line_number, line in enumerate(text.splitlines(), start=1):
        if line == "[[package]]":
            if current is not None:
                packages.append(current)
            current = {}
            continue
        if current is None:
            continue
        match = re.fullmatch(r'([a-z]+) = ("(?:[^"\\]|\\.)*")', line)
        if not match or match.group(1) not in fields:
            continue
        key = match.group(1)
        if key in current:
            raise RuntimeError(f"duplicate Cargo.lock {key} at line {line_number}")
        current[key] = json.loads(match.group(2))
    if current is not None:
        packages.append(current)

    checksums = {}
    for package in packages:
        if "source" not in package or "checksum" not in package:
            continue
        missing = fields - package.keys()
        if missing:
            raise RuntimeError(
                "Cargo.lock registry package is missing fields: "
                + ", ".join(sorted(missing))
            )
        key = (package["name"], package["version"], package["source"])
        if key in checksums:
            raise RuntimeError(f"duplicate Cargo.lock package: {key}")
        checksums[key] = package["checksum"]
    if not checksums:
        raise RuntimeError("Cargo.lock did not contain registry package checksums")
    return checksums


def generate(repo: Path) -> str:
    packages = production_packages(repo)
    by_name_version = {
        (package["name"], package["version"]): package for package in packages
    }
    # Donors can be outside the production graph, so load the complete resolved
    # metadata once. Cargo.lock still pins their exact source and checksum.
    all_metadata = cargo_metadata(repo, TARGETS[0])
    for package in all_metadata["packages"]:
        by_name_version.setdefault((package["name"], package["version"]), package)
    checksums = locked_checksums(repo)

    package_rows = []
    text_users: dict[str, list[str]] = defaultdict(list)
    texts: dict[str, str] = {}
    project_license = read_notice(repo / "LICENSE")

    for package in packages:
        if package["name"] == "HuntProxy" and package.get("source") is None:
            continue
        validate_license_expression(package)
        source = package.get("source")
        if not source or not source.startswith("registry+"):
            raise RuntimeError(
                f"unsupported dependency source for {package['name']} {package['version']}: {source}"
            )
        checksum = checksums.get((package["name"], package["version"], source))
        if not checksum:
            raise RuntimeError(
                f"Cargo.lock checksum is missing for {package['name']} {package['version']}"
            )
        crate_url = (
            f"https://static.crates.io/crates/{package['name']}/"
            f"{package['name']}-{package['version']}.crate"
        )
        package_rows.append(
            f"- {package['name']} {package['version']} | {package['license']} | "
            f"{crate_url} | sha256 {checksum}"
        )

        root = Path(package["manifest_path"]).parent
        notices = [
            (path.relative_to(root).as_posix(), read_notice(path))
            for path in license_files(root)
        ]
        key = (package["name"], package["version"])
        if not notices and key in LICENSE_DONORS:
            for donor_name, donor_version, donor_path in LICENSE_DONORS[key]:
                donor = by_name_version.get((donor_name, donor_version))
                if donor is None:
                    raise RuntimeError(
                        f"license donor is unavailable: {donor_name} {donor_version}"
                    )
                path = Path(donor["manifest_path"]).parent / donor_path
                notices.append(
                    (f"upstream workspace license ({donor_name}/{donor_path})", read_notice(path))
                )
        elif not notices and key == ("yasna", "0.5.2"):
            notices.extend(
                (
                    ("upstream LICENSE-APACHE at b7e65f9", project_license),
                    ("upstream LICENSE-MIT at b7e65f9", YASNA_MIT),
                )
            )
        if not notices:
            raise RuntimeError(
                f"no license/notice text found for {package['name']} {package['version']}"
            )

        for label, notice in notices:
            digest = hashlib.sha256(notice.encode("utf-8")).hexdigest()
            texts.setdefault(digest, notice)
            text_users[digest].append(f"{package['name']} {package['version']} ({label})")

    mpl_packages = [
        package
        for package in packages
        if package["name"] != "HuntProxy" and "MPL-2.0" in package["license"]
    ]
    lines = [
        "HuntProxy Rust dependency notices",
        "=================================",
        "",
        "Generated by scripts/prepare-rust-notices.py from Cargo.lock and the",
        "normal/build dependency graphs for the four published targets. Dev-only",
        "dependencies are excluded. Vendored license, notice, copying, and copyright",
        "files inside dependency archives are included recursively. Identical texts",
        "are emitted once and list every package/file that uses them.",
        "",
        "Published targets:",
        *[f"- {target}" for target in TARGETS],
        "",
        "Locked production packages:",
        *package_rows,
    ]
    if mpl_packages:
        lines.extend(
            [
                "",
                "MPL-2.0 source availability:",
                "The exact corresponding source archives remain available at the pinned",
                "download URLs below. Each archive checksum is recorded in the package list.",
            ]
        )
        for package in mpl_packages:
            lines.append(
                f"- {package['name']} {package['version']}: "
                f"https://static.crates.io/crates/{package['name']}/"
                f"{package['name']}-{package['version']}.crate"
            )

    lines.extend(["", "Deduplicated license and notice texts:"])
    for index, digest in enumerate(sorted(texts), start=1):
        users = sorted(set(text_users[digest]))
        lines.extend(
            [
                "",
                f"--- Text {index:03d} (sha256 {digest}) ---",
                "Used by:",
                *[f"- {user}" for user in users],
                "",
                texts[digest].rstrip(),
            ]
        )
    output = "\n".join(lines) + "\n"
    if len(output.encode("utf-8")) > MAX_NOTICE_BYTES:
        raise RuntimeError(
            f"generated notices exceed {MAX_NOTICE_BYTES} bytes; review deduplication"
        )
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("RUST_THIRD_PARTY_NOTICES.txt"),
    )
    args = parser.parse_args()
    repo = Path(__file__).resolve().parent.parent
    output = args.output if args.output.is_absolute() else repo / args.output
    generated = generate(repo)
    if args.check:
        try:
            existing = output.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"missing generated Rust notices: {output}", file=sys.stderr)
            return 1
        if existing != generated:
            print(
                "generated Rust notices are stale; run scripts/prepare-rust-notices.py",
                file=sys.stderr,
            )
            return 1
        print(f"Rust dependency notices are current ({len(generated.encode('utf-8'))} bytes)")
        return 0
    output.write_text(generated, encoding="utf-8")
    print(f"Wrote {output} ({len(generated.encode('utf-8'))} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
