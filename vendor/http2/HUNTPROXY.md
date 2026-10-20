This is the MIT-licensed `http2` 0.5.19 crate, pinned by HuntProxy and Wreq.

The upstream source changes are:

- `src/proto/streams/streams.rs`: a request's
`StreamDependency` extension overrides the connection's default HEADERS priority.
Requests without the extension retain upstream behavior. HuntProxy uses this for
measured Chromium document navigation priority without creating separate pools
or changing resource requests.
- `src/hpack/encoder.rs`: strings use Huffman coding only when it reduces their
encoded length, matching native Chromium. Values, indexing and decoder behavior
are unchanged. A regression covers raw short values and compressed longer values.
Existing byte expectations for equal-size strings are updated in the encoder and
`src/frame/headers.rs` continuation tests; frame boundaries remain unchanged.

The upstream 0.5.20 release and current main branch did not expose a per-request
priority option when checked on 2026-10-20. Replace this patch with a maintained
upstream API when one becomes available, retaining the shared-connection wire
regression test in `src/transport/mod.rs`.
