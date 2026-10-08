# Release Sync — spec

After a GitHub release, Release Sync publishes or updates the protocols, codes
and apps that changed, signed by the session's identity. It lives in the Mac
app's sidebar, under Tools below SSH (Release Sync). Its logic is in FCDomain (`ReleaseSync/`) and is
covered by `FCDomainTests/ReleaseSync`.

**The rules are FVEP11 Release** (`Freeverse/Protocols/FVEP/FVEP11V1_Release.md`):
DIDs, the code archive, the PID row, identity across versions, links,
`home` keys and the manifest format. Where this file and FVEP11 differ,
FVEP11 wins; this file describes how Freer for macOS implements it (the UI,
review, pending, approval, the run log).

The same file is kept in `FreerForMac/RELEASE_SYNC_SPEC.md` and
`Freeverse/RELEASE_SYNC_SPEC.md`. Change both together. Any other client that
carves these registrations must produce the same DIDs from the same manifest.

Status: implemented on branch `release-sync`, 2026-10-08. Not carved yet.

## Rules

1. **Identity.** An entity's on-chain id (`pid`, `codeId`, `aid`) is the txid
   of its `publish` and never changes. A new version is an `update` of the
   same id, with a new DID. A higher `V<n>` of a protocol document updates
   the same pid.
2. **DID** = double SHA-256 of the entity's bytes, lowercase hex, in byte
   order (not reversed like a txid):
   - protocol: the `.md` file, as carved (see rule 6);
   - code: the module's source archive ([Code archive](#code-archive));
   - app: the release asset; one `downloads` entry per app.
3. **`home`** is a `Map<String,String>` for all three (FEIP1V7 and FEIP2V7 fixed
   on 2026-10-08). Release Sync sets:
   - protocol `src` = the GitHub blob URL on the clone's current branch;
   - code `src` = the tree URL at the tag, and `zip` = the archive asset URL;
   - app `src` = the release page.

   Keys already on chain are kept.
4. **Order:** protocols, then codes, then apps. A txid is known when the carve
   is broadcast, so a code can reference a pid carved moments earlier.
5. **Granularity:**
   - Freeverse: one Code per Maven leaf module, one App per release jar/war.
     FC-SDK.jar is a library, not an app.
   - FreerForMac, Freer (Android), FreeverseExplorer: one Code for the whole
     repo, one App.
6. **The PID row.** A `publish` leaves the Summary table's `|PID||` empty. An
   `update` writes the pid into that row **before** hashing, so the carved
   DID is of a document that names its own id. The edited files are left in
   the working tree for the user to commit. A document whose only difference
   from the chain is that its PID row is still empty counts as unchanged.
7. **DISK.** Every `.md` and every code archive is first copied into the app's
   own file store and registered as a HAT in the signer's Files. It is then
   carved onto DISK unencrypted and permanently (`HatSyncService.uploadRaw`,
   `permanent: true`), so anyone can fetch it by the DID on chain. A DID that
   DISK already holds permanently is not uploaded again.
8. **GitHub.** Code archives are also uploaded to the release as
   `<name>-<tag>.zip` (`gh release upload --clobber`). App DIDs come from
   GitHub's SHA-256 asset digest (the double hash is the SHA-256 of the
   single one), so nothing has to be downloaded. An asset without a digest
   is downloaded and hashed instead.
9. **At most 20 unconfirmed carves.** At 20, the run polls every 30 s until
   records have absorbed their carves (publish: the record exists; update:
   its `lastTxId` is the carve's txid).
10. **Approval.** Each carve goes through the wallet's usual approval, like
    any other carve. With "confirm before signing" on, the transaction dialog
    shows each one before it is signed and broadcast, and declining one skips
    it (its dependants fail as unresolved). With the setting off, carves go
    out without a dialog. A carve from a nobody FID is always shown
    (NOBODY_SPEC.md).
11. **Signer.** Records are matched against the registry of the session's live
    FID, and only that FID can update them. The Freeverse protocols on chain
    belong to `FJYN3D7x4yiLF692WUAe7Vfo2nQpYDNrC7`. Under any other FID, every
    entity would be a new publish.

## Review before carving

"Review each record before carving" (on by default, remembered) opens the
existing Publish or Update sheet for each carve, in review mode, before
anything is written, uploaded or signed. The sheet does not carve; it
returns the fields, and the run carves them through the usual approval.

- **Carve:** carve the shown fields. **Skip:** leave the record out; nothing
  is written to its document, DISK or GitHub. Records that link to a
  skipped publish fail as unresolved; a skipped update leaves its existing
  id usable. **Stop Run:** end the run.
- **One sheet for the run.** The review sheet stays open from the first
  record to the last. After Carve it shows what the carve is doing (storing
  on DISK, uploading to GitHub, signing and broadcasting, waiting for a
  block). The approval dialog is its own window and opens on top. Each
  review page starts with how the previous record went (carved with its
  txid, skipped, or failed with the reason) and "Record n of N". Stop Run
  during a carve stops after that carve, so a broadcast is never left in
  doubt; during a wait for a block it stops at once.
- **Locked fields** come from the repo:
  - protocol: name, type, sn, ver, lang, desc, DID (all from the .md);
  - code: name, ver, DID;
  - app: stdName, ver, downloads.

  To change them, change the repo and scan again.
- **Code and app edits** to desc, langs, types, localNames and the
  protocol/code links are written back to the repo's
  `freeverse-release.json` after the carve. Only fields changed in review
  are written, so a description clipped to fit is never written back. A
  link offered from the manifest keeps its name (`FEIP1`); one added by id
  is stored as the raw 64-hex id. The file is re-encoded (pretty-printed)
  when written.
- `home`, `waiters`, `preDid` and services are not in the manifest; edits to
  them live on chain and are carried into later updates. `home.src` and
  `home.zip` are regenerated each release.

## Repo manifest: `freeverse-release.json`

There is one manifest at each repo root. It records only what cannot be
inferred from the tree.

```json
{
  "github": "nobodyoffc/Freeverse",
  "protocolDirs": ["Protocols"],
  "codes": [
    { "name": "FC-JDK", "path": "FC-JDK", "langs": ["Java"], "desc": "…",
      "protocols": ["FEIP0", "FUDP0"] }
  ],
  "apps": [
    { "stdName": "FapiServer", "asset": "FapiServer.jar", "os": "java",
      "types": ["server"], "desc": "…", "localNames": { "en": "…" },
      "codes": ["FC-JDK"], "protocols": ["FAPI0"] }
  ]
}
```

- A protocol or code reference may also be a raw 64-hex id.
- A protocol reference is `<TYPE><SN>` (`FEIP1`). It resolves to this run's
  record of that type and sn, or to the signer's on-chain record.
- A code reference is a code `name`, optionally `<repo>/<name>`. It resolves
  to this run's code, or to the signer's on-chain code.
- `asset` may use `*` (`Freer-*.dmg`).
- `"path": "."` makes the whole repo one code.
- A manifest change (desc, langs, types, links) is itself a reason to update
  a code or app.

## Protocol documents

A protocol document is any file under `protocolDirs` named
`<TYPE><SN>V<VER>_<Name>.md`. Fields are read as the retired Java
`PublishProtocols` CLI read them:

- **Summary table:** the first pipe table under `## Summary`. Failing that, the
  first one before `## Contents`, else the first in the file. The PID filler
  uses the same table.
  - `Title` → `name`, `Type`, `SN`, `Version`/`Ver`, `Lang`/`Language` (default
    `en`), `PID` (read only when it holds a 64-hex txid).
- **Validation:** `Type`, `SN` and `Version` must agree with the file name. A
  change proposal (`FIMP (change proposal)`) is therefore skipped.
- **`desc`:** the Abstract section on one line. Code fences and sub-headings
  are dropped, `[text](link)` becomes `text`, and `**` and backticks are
  removed. It is clipped at a word, with "…", to fit the OP_RETURN.
- **Per type and sn,** only the highest version is used. Two different files
  with that same version are reported, and the first by path is used.

Change is decided by the DID alone. On 2026-10-08, 41 documents matched the
chain byte for byte. Of those, 32 descriptions equal this extraction; nine
FTSP descriptions were edited by hand at carve time. An update overwrites
such a hand edit.

## Matching

| | key | also |
|---|---|---|
| protocol | `type`+`sn` | the document's PID, when present, wins |
| code | `name` | |
| app | `stdName` | |

The result of matching is one of:
- **publish:** no record has the key.
- **update:** the record differs.
- **unchanged:** the record matches.
- **blocked:** the record is closed, or stopped. The parsers ignore an update
  to an inactive record, so it must be recovered first.
- **choose:** several records share the key. The user picks one in the review
  list.
- **invalid:** for example, a PID that the signer does not own.
- **pending:** carved by an earlier run, per the run log, and not on chain
  yet. The id is already known (the txid for a publish), so codes and apps
  can reference it. It is not offered for carving. After 2 hours it is
  marked "possibly dropped", with **Carve Again**, which forgets the logged
  carve. A pending publish stays pending even if the document changed
  since: a second publish would make a duplicate record, so the edit
  becomes an update once the publish lands. An update with a new DID on top
  of a pending update is offered, since a later update supersedes it.
- **orphan:** on chain but not in the repos. Orphans are listed and never
  stopped automatically.

## Code archive

`git archive` is not byte-stable. It writes the commit id into the archive
comment, and git 2.33 (installed here) has no `--mtime`, so archiving a tree
stamps the current time. Release Sync writes the zip itself
(`DeterministicZip`):

- entries come from `git ls-tree -r --full-tree <tag> -- <path>/`, read with
  `git cat-file --batch`, and are sorted by UTF-8 path;
- each entry is stored as `<name>/<path inside the module>`. Submodules are
  left out; a symlink is stored as a file holding its target;
- every entry is dated 1980-01-01 00:00. There are no extra fields, no
  comment and no directory entries. Unix mode is 0755 for git mode 100755,
  otherwise 0644;
- an entry is deflated (`COMPRESSION_ZLIB`, zlib level 5) when that is
  smaller, otherwise stored.

`testTheBytesArePinned` pins one archive's DID, so a macOS update that changed
the encoder would fail that test before it changed every code's DID.

## Run log and resume

Each carve is appended to `<dataDirectory>/release-sync/<FID>.json` with its
key, id, txid and DID. If a later run plans the same carve for the same DID,
it is skipped and the logged id is used, so an interrupted run resumes
without carving anything twice. The same log marks entities as
**pending** until the chain shows the carve. Delete the file to forget the
log.

## Files

| Part | Path |
|---|---|
| Manifest | `FCDomain/ReleaseSync/ReleaseManifest.swift` |
| Protocol documents | `ProtocolDoc.swift` |
| Zip | `DeterministicZip.swift` |
| git / gh | `ReleaseTools.swift` |
| Scan | `ReleaseScanner.swift` |
| Chain | `ReleaseChainState.swift` |
| Plan | `ReleasePlan.swift` |
| Run | `ReleaseRunner.swift`, `SessionReleaseBackend.swift` |
| UI | `Sources/FreerForMac/Views/Panes/ReleaseSyncToolView.swift` (`WalletPane.releaseSync`) |
| Tests | `FCDomainTests/ReleaseSync/ReleaseSyncTests.swift` |
| Live tests | `ReleaseSyncLiveTests.swift` (`RELEASE_SYNC_FAPI`, `RELEASE_SYNC_OWNER`, `RELEASE_SYNC_REPO(S)`) |
