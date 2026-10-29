# @zeroj/hash

Ordinary SHA-256, SHA-512 and unkeyed BLAKE2b. These functions do not build ZK circuits.
`createHash(runtime)` uses WebCrypto for SHA and Wasm for BLAKE2b; select
`{ shaBackend: 'wasm' }` for Java implementation parity. The input bound is 256 KiB per call.
