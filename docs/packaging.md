# Packaging

## Release binary

```bash
cargo build --release
# artifact: target/release/bb
```

Targets planned for CI: Linux glibc amd64/arm64, macOS amd64/arm64.

## Homebrew (draft)

```ruby
class Bb < Formula
  desc "Local-first agent-safe HTTP workbench"
  homepage "https://github.com/example/bb"
  url "…"
  sha256 "…"
  depends_on "rust" => :build
  def install
    system "cargo", "install", *std_cargo_args
  end
end
```

## Docker

```bash
docker build -t bb:local .
docker run --rm -p 17890:17890 -p 17891:17891 -v bb-data:/data bb:local
```

Browser engines (Lightpanda/Chromium) remain optional installable artifacts.

## Project license

Owner must select a project license before public distribution. Default dependency path uses exact-pinned Apache-2.0 Wreq prereleases (see ADR 0001).
