# 0010 — Encryption descent in the resolver + `CredentialSource` injection

**Status:** Accepted (2026-07-19)

## Context

The headline layer stack the VFS exists to auto-resolve is `E01 → GPT → BitLocker →
NTFS`. Until now the resolver ([`SourceOpen::open`], ADR 0007) descended
filesystems, volume systems, containers, and archives (ADR 0008) — but **not**
full-disk encryption. ADR 0007 named this exact gap as a tracked follow-up: the
encryption layer between a volume and its filesystem was never opened, so an
encrypted volume resolved to `None` (a "clean unknown") even with the key in hand.
The `EncryptionLayer`/`CredentialSource`/`EncryptionOpen` contracts already exist in
the leaf; what was missing is the descent that drives them and the seam that gets
credentials to it.

Two facts about real FDE shape the design, and they pull in opposite directions:

- **Signature-detectable, volume-backed** encryption — BitLocker (`-FVE-FS-`), LUKS
  (`LUKS\xba\xbe`), FileVault/CoreStorage — carries a plaintext header magic. A
  probe reads the sniff window and returns a definite verdict. This layer sits
  *after* the volume system (the `BitLocker` in `E01 → GPT → BitLocker → NTFS`): the
  volume descent hands each partition to the resolver, and at that inner node the
  encryption header is the source's magic.
- **Signature-less, file/disk-backed** encryption — VeraCrypt/TrueCrypt — has **no
  plaintext magic by design** (plausible deniability). Its header is
  indistinguishable from random data until decrypted. A probe *cannot* confirm it;
  it can only say "I can't rule this out — try me with credentials." A whole-volume
  file that decrypts is VeraCrypt; one that doesn't is random data (or a different
  scheme). There is nothing to detect ahead of the attempt.

A single "probe then open" model cannot serve both without conflating "I recognized
this" with "I couldn't rule this out." If a VeraCrypt probe reported the same
positive verdict a BitLocker probe does, it would claim *every* unrecognized source,
shadowing real filesystems and breaking the `Ok(None)` "clean unknown" contract that
the whole resolver rests on.

Credentials add a second constraint. A [`PathSpec`] is an address, not a keychain
(ADR 0002 — identity is opaque and serializable; a spec pasted from a report must
re-open without carrying secrets). So keys cannot live in the locator; they must be
injected at resolve time and threaded to `EncryptionLayer::open`.

## Decision

### 1. `probe()` is tri-state, and the verdict decides the failure semantics

[`Confidence`] already has three arms; encryption uses all three with distinct
meaning:

- **`Yes`** — a signature scheme matched its header magic. A *positive
  identification*.
- **`Maybe`** — a signature-less scheme cannot rule itself out. **Not** an
  identification; a request to attempt.
- **`No`** — ruled out.

The verdict determines what a failed `open`/decrypt means — reusing, not bending,
the resolver's existing "a positive verdict whose `open` fails propagates loud" rule
(ADR 0007):

| Verdict | On `open`/decrypt failure | Why |
|---|---|---|
| `Yes` (BitLocker/LUKS/FileVault) | **Propagate loud** | The source *is* identified encryption. A wrong/absent key is a real, nameable condition (`NeedCredentials` / `Decode` with header bytes) — surfacing it loud is fail-loud (an encrypted volume must never masquerade as a clean unknown). |
| `Maybe` (VeraCrypt) | **Fall through to the next opener / `None`** | A `Maybe` was never an identification. A failed decrypt is indistinguishable from random data, so treating it as an error would make every unrecognized blob error and break the empty-source contract. |

This is the crux: the tri-state verdict, not a special case, is what lets the two
models coexist. Signature failures are loud because the source was identified;
credential-attempt failures are silent because nothing was.

### 2. Resolver ordering — signature schemes eager, credential-attempt schemes last resort

At each resolve node the descent runs in this order:

1. **Filesystems** — a plaintext filesystem claims the source immediately (a
   decrypted NTFS mounts here on the next recursion).
2. **Volume systems** — descend each volume and recurse (the encryption node is
   reached *inside* this recursion, matching "after the volume layer").
3. **Encryption — signature (`Yes`) pass** — eager. On `Yes`: construct the layer
   (`EncryptionOpen::open`), decrypt (`EncryptionLayer::open(creds)`), push
   `Layer::Encryption { scheme }`, and recurse on the decrypted source. A `Maybe`
   here is only *recorded*, not attempted.
4. **Containers**, then **5. Archives** (ADR 0008) — unchanged.
6. **Encryption — credential-attempt (`Maybe`) pass** — **last resort.** Only
   reached when nothing above claimed the source. For each recorded `Maybe`,
   attempt construct + decrypt with the supplied credentials; on success push
   `Layer::Encryption { scheme }` and recurse, on failure continue. Exhausting them
   yields `Ok(None)`.

Ordering the credential-attempt pass dead last is the load-bearing choice: a wrong
VeraCrypt attempt can never shadow a real filesystem, volume, container, archive, or
signature-detected encryption, because all of those had their turn first. VeraCrypt
is tried only against a source that everything else has already declined.

### 3. `CredentialSource` is injected through the resolve call, never stored in the locator

Credentials reach the descent through a new resolver entry point:

```rust
fn open_with_credentials(&self, source, spec, depth, creds: &dyn CredentialSource)
    -> VfsResult<Option<Resolved>>;
```

`open(source, spec, depth)` is retained as a provided method that delegates with a
new leaf default, [`NoCredentials`] (a `CredentialSource` that offers nothing). This
keeps every existing call site — the 24 resolve tests and the out-of-repo engine —
compiling unchanged, while the encryption descent threads `creds` through every
recursion. The credential context is a *call parameter*, never a field of
[`PathSpec`]: the locator stays a pasteable, secret-free address (ADR 0002), and a
caller re-supplies credentials on re-open.

`NoCredentials` is the **secure-by-default** context: with no keys supplied, a
signature scheme surfaces `NeedCredentials` loudly (per §1) and a credential-attempt
scheme simply fails to decrypt and falls through — an encrypted volume is never
silently skipped nor guessed at.

### 4. `Layer::Encryption { scheme }` is the locator node

A resolved encryption layer pushes `Layer::Encryption { scheme: EncryptionScheme }`
onto the `PathSpec`, with the canonical URI token `encryption:<scheme>` (e.g.
`encryption:bitlocker`, `encryption:veracrypt`), round-tripping byte-for-byte like
every other layer and rejecting an unknown scheme token loudly. This mirrors
`Layer::Container` / `Layer::Volume` / `Layer::Archive`: the descent records *which*
scheme decrypted the node, so the stack `E01 → GPT → BitLocker → NTFS` serializes,
re-opens, and is what a report cites. The node carries the scheme only — never the
credentials that opened it.

## Consequences

- The headline `E01 → GPT → BitLocker → NTFS` auto-resolves end-to-end once a
  BitLocker `EncryptionOpen` is wired into the engine's `default_openers()` and a
  `CredentialSource` is passed to `open_with_credentials`.
- **What the readers/engine build on this:**
  - A signature reader (bitlocker/luks/filevault `EncryptionOpen`) returns
    `Confidence::Yes { how }` from `probe` on its header magic, and constructs its
    `EncryptionLayer` from the source; `EncryptionLayer::open(creds)` does the key
    derivation and returns the decrypted `DynSource`. Its `open` **must** error
    (`NeedCredentials` / `Decode` with the header bytes) on a bad/absent key — the
    resolver relies on that to fail loud.
  - A credential-attempt reader (veracrypt `EncryptionOpen`, the template already in
    `veracrypt-forensic`) returns `Confidence::Maybe` from `probe` (never `Yes`) and
    lets `EncryptionLayer::open(creds)` be the sole arbiter — a failed decrypt is the
    "not this scheme" signal the resolver turns into fall-through.
  - The engine passes a real `CredentialSource` (keys/passphrases/recovery keys) to
    `open_with_credentials`; `Vfs::open(path)` with no keys uses `NoCredentials`.
- **Behavioral-semver note (ADR 0007):** encryption descent changes resolver output
  without changing public types. The eager-signature-vs-last-resort ordering and the
  `Yes`-loud / `Maybe`-silent failure rule are the invariants a golden-stack fixture
  must pin; a probe-ordering change is a behavioral change even under
  `#[non_exhaustive]`.
- Sibling to ADR 0008 (archives as a first-class resolved layer): both add a layer
  to the same recursive descent and both push a `Layer` node; encryption differs
  only in needing an injected credential context and in the two-model probe
  semantics above.

## Version impact

- `forensic-vfs` (leaf) 0.4.1 → **0.4.2** — additive: `NoCredentials` +
  re-export. `Layer::Encryption`, the URI token, and the `EncryptionOpen` trait
  already shipped in 0.4.
- `forensic-vfs-resolver` 0.1.2 → **0.1.3** — additive: `open_with_credentials`
  (with `open` retained as a delegating default) + the encryption descent.
