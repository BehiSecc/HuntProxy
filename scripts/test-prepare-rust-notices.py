#!/usr/bin/env python3
"""Checks for locked Rust dependency provenance."""

import importlib.util
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "rust_notices", Path(__file__).with_name("prepare-rust-notices.py")
)
assert spec is not None and spec.loader is not None
notices = importlib.util.module_from_spec(spec)
spec.loader.exec_module(notices)


class SourceProvenanceChecks(unittest.TestCase):
    def setUp(self):
        self.repo = Path("/tmp/artis/huntproxy-notices-test")

    def test_registry_checksum_is_recorded(self):
        source = "registry+https://github.com/rust-lang/crates.io-index"
        package = {"name": "example", "version": "1.2.3", "source": source}
        sources = {("example", "1.2.3", source): "a" * 64}
        value = notices.source_provenance(package, self.repo, sources)
        self.assertIn("example-1.2.3.crate", value)
        self.assertIn("sha256 " + "a" * 64, value)

    def test_pinned_git_revision_is_recorded(self):
        revision = "b" * 40
        source = f"git+https://github.com/example/lib?rev={revision}#{revision}"
        package = {"name": "lib", "version": "1.0.0", "source": source}
        sources = {("lib", "1.0.0", source): None}
        value = notices.source_provenance(package, self.repo, sources)
        self.assertIn(f"https://github.com/example/lib/tree/{revision}", value)

    def test_unpinned_or_unlocked_git_is_rejected(self):
        revision = "b" * 40
        source = f"git+https://github.com/example/lib?rev={revision}#{'c' * 40}"
        package = {"name": "lib", "version": "1.0.0", "source": source}
        with self.assertRaisesRegex(RuntimeError, "unsupported dependency source"):
            notices.source_provenance(package, self.repo, {("lib", "1.0.0", source): None})
        with self.assertRaisesRegex(RuntimeError, "Cargo.lock source is missing"):
            notices.source_provenance(package, self.repo, {})

    def test_only_the_expected_vendored_crate_is_allowed(self):
        package = {
            "name": "http2",
            "version": "0.5.19",
            "source": None,
            "manifest_path": str(self.repo / "vendor/http2/Cargo.toml"),
        }
        sources = {("http2", "0.5.19", None): None}
        self.assertIn("vendor/http2 (modified)", notices.source_provenance(package, self.repo, sources))
        package["manifest_path"] = str(self.repo / "elsewhere/Cargo.toml")
        with self.assertRaisesRegex(RuntimeError, "unsupported dependency source"):
            notices.source_provenance(package, self.repo, sources)


if __name__ == "__main__":
    unittest.main()
