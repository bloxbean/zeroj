# @zeroj/runtime

Experimental, lazy Java-to-Wasm worker runtime for browsers and Node. Register pinned bundle
descriptors with `createRuntime({ bundles })`. `experimentalSecrets: true` permits research
secret operations; it does not establish side-channel safety. Always dispose the runtime.
