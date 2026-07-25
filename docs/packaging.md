# Packaging

## Release binary

```bash
cargo build --release
# artifact: target/release/HuntProxy
```

Targets planned for CI: Linux glibc amd64/arm64, macOS amd64/arm64.

## Homebrew (draft)

```ruby
class Huntproxy < Formula
  desc "Local-first agent-safe HTTP workbench"
  homepage "https://github.com/example/HuntProxy"
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
docker build -t huntproxy:local .
docker run --rm -p 17890:17890 -p 17891:17891 -v huntproxy-data:/data huntproxy:local
```

Browser engines (Lightpanda/Chromium) remain optional installable artifacts.

## Project license

Owner must select a project license before public distribution. Default dependency path uses exact-pinned Apache-2.0 Wreq prereleases (see ADR 0001).
