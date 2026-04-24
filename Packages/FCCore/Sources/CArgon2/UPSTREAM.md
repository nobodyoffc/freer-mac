# CArgon2 — vendored Argon2 reference implementation

Source: https://github.com/P-H-C/phc-winner-argon2
Version: tag `20190702` (commit `62358ba2123abd17fccf2a108a301d4b52c01a7c`)
License: CC0 1.0 / Apache 2.0 dual (see `LICENSE`)

Files vendored (unmodified):
- `include/argon2.h`            ← upstream `include/argon2.h`
- `argon2.c`, `core.{c,h}`      ← upstream `src/`
- `encoding.{c,h}`, `thread.{c,h}`, `ref.c`  ← upstream `src/`
- `blake2/blake2.h`, `blake2b.c`, `blake2-impl.h`, `blamka-round-ref.h`  ← upstream `src/blake2/`

Deliberately **not** vendored:
- `src/opt.c`, `src/blake2/blamka-round-opt.h` — SSE/AVX variants. We use
  `ref.c` which compiles on both arm64 and x86_64 without intrinsics.
- `src/bench.c`, `src/genkat.{c,h}`, `src/run.c`, `src/test.c` — standalone
  CLI tools with their own `main()`.

To bump the version: `rm -rf` this directory, clone upstream at the new tag,
repeat the file list above, update this file with the new commit hash,
and run the CArgon2 + FCCore tests.
