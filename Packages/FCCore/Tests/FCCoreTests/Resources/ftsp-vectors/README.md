# FTSP cross-implementation vectors

Language-neutral test vectors for the Freeverse crypto formats. They are generated from **FC-JDK**, the reference implementation ([FTSP0](../FTSP0V1_FTSP.md) §5). **Every implementation MUST pass all of them:** FC-JDK, `Safe/FC-AJDK`, `Freer/FC-AJDK`, SafeForMac (through FC-JDK) and FreerForMac.

All byte values are lowercase hex unless the field name says `Base64`. Inputs are the [FTSP0 §2.1](../FTSP0V1_FTSP.md#21-shared-example-keys-developer-json-samples) shared example keys: plaintext `Hello world!`, password `MyPassword`, symkey `dc1e7c03…`, fidA/fidB key pairs, and the fixed IVs `000102…0b` (12 bytes) and `000102…0f` (16 bytes).

| File | Spec | What an implementation checks |
|---|---|---|
| `kdf.json` | FTSP25, FTSP29 | `deriveSymkey(password, salt)` equals `symkey`; `kdfId` maps to `kdf`. |
| `phrase.json` | FTSP28 | Deriving from `phraseUtf8Hex` with `salt` gives `priKey32`. Only `conformant: true` entries are how new keys are made; the rest exist to recover keys from older builds. |
| `cipher-json.json` | FVEP8 | Decrypting `cipherJson` with `secret` gives `plaintextHex`. For Password, the KDF that worked equals `derivedWith`, including when the JSON has no `kdf` (`kdfRecorded: false`). |
| `bundle.json` | FTSP30 | `expect: "decrypt"`: parsing gives `alg`, `type` and `kdfRecorded`, and decrypting with `secret` gives `plaintextHex`. `expect: "reject"`: the parser must refuse the bytes. `canonical: true`: re-serialising the parsed bundle reproduces the bytes exactly. |
| `algorithms.json` | FTSP11–27 | Every other cipher profile — ChaCha20 variants, the legacy ECC CBC and P7 profiles and X25519 — as JSON (`cipherJson`) and bundle (`bundleHex`); BitCore only as its raw `encbufHex`, since Bitcore ciphers have no JSON form. `expect: "decrypt"` must give `plaintextHex`; `expect: "reject-decrypt"` is a tampered cipher that must not decrypt successfully. `knownGaps` lists tampering FC-JDK does not yet detect. |

`secret` holds one of `symkey`, `password`, or `prikey` (plus the peer's `pubkey` for AsyTwoWay).

## Regenerating

From the Freeverse repository root:

```
mvn -q test-compile exec:java -pl FC-JDK -Dexec.classpathScope=test \
    -Dexec.mainClass=core.crypto.CryptoVectorsGenerator \
    -Dexec.args="$PWD/Protocols/FTSP/vectors"
mvn test -pl FC-JDK -Dtest=CryptoVectorsTest
```

Symmetric, password and phrase vectors are deterministic. Asymmetric ciphers change on every run because the encryptor picks the ephemeral key, but they still decrypt with the same `secret`. When `CryptoDataByte.WRITE_PASSWORD_BUNDLE_WITH_KDF` is switched on, regenerate: type-4 bundles become `canonical` and type-3 bundles stop being.
