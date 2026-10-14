#!/usr/bin/env python3
"""Regression checks for release-asset validation across Zstd encoders."""

import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch


sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "release_assets", Path(__file__).with_name("prepare-release-assets.py")
)
assert spec is not None and spec.loader is not None
assets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assets)


class ReleaseAssetChecks(unittest.TestCase):
    def setUp(self):
        root = Path("/tmp/artis")
        root.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(
            prefix="huntproxy-release-assets-test-", dir=root
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.existing = self.root / "existing" / "plugins-catalog.tar.zst"
        self.candidate = self.root / "candidate" / "plugins-catalog.tar.zst"
        self.existing.parent.mkdir()
        self.candidate.parent.mkdir()
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            content = b'{"role":"member","scope":"workspace"}\n' * 100
            entry = tarfile.TarInfo("plugins/workspace/index.js")
            entry.size = len(content)
            entry.mode = 0o644
            archive.addfile(entry, io.BytesIO(content))
        self.payload = output.getvalue()

    def compress(self, path, payload, *options):
        source = path.parent / "catalog.tar"
        source.write_bytes(payload)
        subprocess.run(
            ["zstd", "-q", "-f", *options, str(source), "-o", str(path)], check=True
        )

    def test_different_encoder_representations_keep_the_same_contents(self):
        self.compress(self.existing, self.payload, "-1", "--no-check")
        self.compress(self.candidate, self.payload, "-19")
        self.assertNotEqual(self.existing.read_bytes(), self.candidate.read_bytes())
        assets.verify_asset(self.existing, self.candidate)

    def test_changed_tar_contents_are_rejected(self):
        self.compress(self.existing, self.payload.replace(b"member", b"owner_"), "-1")
        self.compress(self.candidate, self.payload, "-19")
        with self.assertRaisesRegex(SystemExit, "differs from generated output"):
            assets.verify_asset(self.existing, self.candidate)

    def test_truncated_archive_is_rejected(self):
        self.compress(self.existing, self.payload, "-1")
        self.compress(self.candidate, self.payload, "-19")
        self.existing.write_bytes(self.existing.read_bytes()[:20])
        with self.assertRaisesRegex(SystemExit, "cannot be decoded"):
            assets.verify_asset(self.existing, self.candidate)

    def test_archive_expansion_is_bounded(self):
        self.compress(self.existing, self.payload, "-1")
        with patch.object(assets, "MAX_PLUGIN_EXPANDED_BYTES", 128):
            with self.assertRaisesRegex(SystemExit, "expands beyond the size limit"):
                assets.asset_payload(self.existing)

    def test_encoded_archive_size_is_bounded(self):
        with self.existing.open("wb") as archive:
            archive.seek(assets.MAX_PLUGIN_ARCHIVE_BYTES)
            archive.write(b"\0")
        with self.assertRaisesRegex(SystemExit, "exceeds the encoded size limit"):
            assets.asset_payload(self.existing)

    def test_other_assets_still_require_exact_bytes(self):
        existing = self.existing.with_name("node-runtimes.json")
        candidate = self.candidate.with_name("node-runtimes.json")
        existing.write_bytes(b'{"version":"22.23.2"}\n')
        candidate.write_bytes(existing.read_bytes())
        assets.verify_asset(existing, candidate)
        existing.write_bytes(b'{"version":"22.23.1"}\n')
        with self.assertRaisesRegex(SystemExit, "differs from generated output"):
            assets.verify_asset(existing, candidate)


if __name__ == "__main__":
    unittest.main()
