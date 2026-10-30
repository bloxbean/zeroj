# @zeroj/circuit-lint

Experimental type-aware guardrails for `@zeroj/circuit` authoring. Run
`zeroj-circuit-lint path/to/circuits.ts` using the locally installed package, or import
`lintSymbolic(files)` to receive diagnostics. Tested with TypeScript 5.9.3.

Flags typed symbolic values in JS branch conditions, operators, templates and direct
Boolean/Number/String/BigInt conversions. Use symbolic methods and select() instead.
The checker is not a sandbox or a complete ESLint plugin: any/reflection/aliased conversion
functions can bypass it. Keep definition shapes/constants public; assert intended relations.
Use TypeScript strict compilation alongside lint. This package contains no cryptography or Wasm.
