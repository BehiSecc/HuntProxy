# http2

A Tokio aware, HTTP/2 client & server implementation for Rust.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Crates.io](https://img.shields.io/crates/v/http2.svg)](https://crates.io/crates/http2)
[![Documentation](https://docs.rs/http2/badge.svg)][dox]

More information about this crate can be found in the [crate documentation][dox].

[dox]: https://docs.rs/http2

## Features

- Client and server HTTP/2 implementation.
- Implements the full HTTP/2 specification.
- Passes [h2spec](https://github.com/summerwind/h2spec).
- Focus on performance and correctness.
- Built on [Tokio](https://tokio.rs).

## Non-goals

This crate focuses solely on implementing the HTTP/2 specification. It supports client-side processing based on the original [h2](https://github.com/hyperium/h2) branch, including:

- Pseudo-header permutation for headers frame
- Experimental and permuted settings frame support
- Priority frame support (client-side only)
- Major multi-core concurrency boost for client and server

This crate is now used by [wreq](https://github.com/0x676e67/wreq), which will provide all of these features.

## Usage

To use `http2`, first add this to your `Cargo.toml`:

```toml
[dependencies]
http2 = "0.5"
```

Next, add this to your crate:

```rust
use http2::server::Connection;

fn main() {
    // ...
}
```

## Accolades

The project is based on a fork of [h2](https://github.com/hyperium/h2).
