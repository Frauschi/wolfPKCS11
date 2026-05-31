# Safe Private-Key State I/O for Stateful Hash-Based Signatures

**Scope.** This document is the design reference for persisting the private-key
state of stateful hash-based signature (HBS) schemes — LMS/HSS (RFC 8554)
today, XMSS / XMSS^MT (RFC 8391) in the future — on POSIX-style filesystems.
The goal is OTS-key-reuse prevention under every failure mode that POSIX
exposes (crash, power loss, partial write, restart).

It is structured in three independent parts:

1. **The contract.** What the wolfCrypt read/write callbacks must guarantee
   for the signing primitive to remain secure, expressed without reference
   to any particular OS or project.
2. **The POSIX recipe.** What "durable atomic write" actually means in
   terms of syscalls, in a project-agnostic way.
3. **The wolfPKCS11 realisation.** Concrete functions, structs, and
   policies that implement parts 1 and 2 inside wolfPKCS11. This part
   is the implementation reference; parts 1 and 2 should be reusable
   wholesale in wolfHSM and other consumers.

---

## Part 1 — The Contract

Stateful HBS schemes guarantee unforgeability **only** as long as no
one-time-signature (OTS) leaf is ever used twice. The cryptographic state
is a monotonic leaf counter; a successful signing operation advances it.
Re-using a leaf, even once, computationally leaks enough of the secret
to forge arbitrary messages (BH16, Fluhrer23).

The wolfCrypt LMS and XMSS implementations push the responsibility of
state persistence out through two callbacks. Any layer that wires these
callbacks is the *trusted base* for OTS-no-reuse — including this layer.

### 1.1 The wolfCrypt callback contract

Both LMS (`wc_LmsKey_*`) and XMSS (`wc_XmssKey_*`) expose the same shape:

```c
typedef enum wc_LmsRc (*write_cb)(const byte* priv, word32 privSz, void* ctx);
typedef enum wc_LmsRc (*read_cb)( byte* priv, word32 privSz, void* ctx);
```

The write callback is invoked **synchronously** by `wc_LmsKey_MakeKey` and
`wc_LmsKey_Sign`, once per state advance. The XMSS API is structurally
identical.

The contract is asymmetric in a critical way:

- If the write callback returns `…_RC_SAVED_TO_NV_MEMORY`, wolfCrypt
  **proceeds to release the signature** to the application. The
  callback is asserting that the new state is durable on stable
  storage.
- If the callback returns anything else, wolfCrypt **aborts the sign**;
  no signature bytes leave the wolfCrypt layer.

The whole security argument hinges on the write callback never returning
`SAVED_TO_NV_MEMORY` until the new state has actually reached stable
storage. A buggy implementation that returns success eagerly — for
example, after `write()` but before `fsync()` — silently breaks the
OTS-no-reuse property under power loss.

The read callback symmetrically fills the priv buffer with the
previously persisted state, or returns a failure code.

### 1.2 Requirements on the write path

A correct write callback must satisfy seven properties. They are
independent; each one defends against a specific failure mode.

1. **Atomicity.** The on-disk representation must transition from
   "previous state, complete" to "new state, complete" with no
   externally observable intermediate. A crash mid-write must leave the
   reader with one or the other, never a torn artifact.

2. **Durability.** When the callback returns success, the new state must
   have reached stable storage in a form that survives:
   - process death (any signal, including `SIGKILL`),
   - OS panic and reboot,
   - power loss (the most demanding case — defeats kernel write-back
     caches and disk-internal volatile caches),
   - forced VM termination by the hypervisor.

   "Stable storage" means the data is recoverable on the next boot
   from the same physical media. RAM caches, disk-internal volatile
   caches, and NFS server caches do not qualify.

3. **Ordering.** Persistence must complete *before* the callback returns
   success. wolfCrypt will not re-check; whatever the callback says,
   wolfCrypt acts on.

4. **Confidentiality.** The bytes passed to the callback are private-key
   material. They must be encrypted at rest under a key that does not
   itself live in the same file.

5. **Authenticity & rollback resistance within the file.** A tampered
   state file must be *detected* on next load, not silently used. An
   AEAD with the per-key metadata bound into the AAD (magic, version,
   scheme parameters, the persisted signature counter itself) detects
   every bit-level tamper. AEAD alone does **not** prevent an operator
   from substituting a previous good copy of the file at the
   filesystem level — that is an out-of-band concern (§1.6).

6. **Concurrency**. Two threads, processes, or any other agents that
   could call sign on the same key must serialize over the entire
   sign-and-persist sequence. Otherwise both can read the same state,
   both produce signatures at the same leaf, and both persist
   "advanced" states that point to the same already-used leaf.

7. **Key binding.** The state file is meaningful only for one specific
   key. The persistence layer must encode enough metadata (parameters,
   key identity) into the file that loading it against a different key
   fails closed.

### 1.3 Requirements on the read path

The read callback's job is narrower but the failure modes are equally
fatal:

1. **Authenticity check before use.** If the AEAD tag does not verify,
   the callback must zero the destination buffer and return a failure
   code. Returning silent partial data would let wolfCrypt re-interpret
   garbage as a state, with results ranging from a crash to undefined
   leaf use.

2. **Parameter binding.** The persisted state implicitly belongs to a
   specific parameter set. The reader must verify the persisted
   parameters match the in-memory key's parameters before decrypting.
   A mismatch typically means the wrong key was selected by mistake;
   loading anyway can corrupt the in-memory state machine.

3. **Fail-safe on any I/O error.** Disk read short, ENOSPC, permission
   denied — every error must surface as a read-callback failure, and
   the destination buffer must be zeroed.

### 1.4 Per-key identity

Each key needs a stable identifier that determines its state file path.
Failure modes the identifier must avoid:

- **Drift across reload.** If the identifier of a key on disk depends on
  state external to the key (e.g., insertion order into a table), then
  removing an unrelated key can move the path. Reload then can't find
  the file; or, worse, finds a different key's file.

- **Collision.** Two keys with the same identifier would share a state
  file. Each sign would race-overwrite the other; leaf reuse follows
  immediately. A 64-bit random nonce is the minimum (birthday bound
  ~2^32 keys); larger is fine.

- **Predictability that aids targeted overwrite.** If an attacker can
  predict the identifier of a not-yet-created key, they can pre-place
  a tampered file at that path. Keep the identifier random rather than
  derived from monotonic counters.

### 1.5 Failure handling: the poison flag

Suppose the write callback's persistence step fails after wolfCrypt has
already advanced the in-memory state machine. The on-disk state is the
*old* state (atomicity), the in-memory state is the *new* state, and the
callback returned WRITE_FAIL so wolfCrypt aborted the sign — no
signature was emitted, no leaf was burned.

But the in-memory key is now ahead of disk. A subsequent sign would
write `disk_state + 2` next, skipping over `disk_state + 1` — which is
fine — *unless* the next sign also fails, then unless a later
recovery loses the in-memory state, etc. The whole branch is fragile.

The defensible discipline is: any sign error **poisons the in-memory
key**. A poison flag in the object's metadata is cleared; any subsequent
sign returns "device error" without touching wolfCrypt. Recovery is to
reload from disk (which restores the last *durable* state) and clear the
poison. This requires no leaf to ever be used twice, by construction.

### 1.6 What the contract does NOT promise

These are out-of-band concerns that no callback-level discipline can
fix:

- **Filesystem-level rollback.** An operator who copies the state file
  and later restores it can roll back leaf state. The AEAD doesn't
  prevent this — the substituted file still verifies, because it was a
  legitimate state. Defenses live above this layer: documentation
  ("do not back up the token directory"), TPM-backed monotonic
  counters, or sectorization (§5.3 of `draft-ietf-pquip-hbs-state`).

- **VM snapshot revert / host migration.** Same shape as filesystem
  rollback, executed by the hypervisor.

- **Process forking after key load.** Both parent and child see the
  same in-memory state. Both can sign; only one writes back; the
  other's signature is at a now-shared leaf. Pre-empt with
  `pthread_atfork` that invalidates state in the child.

- **Storage on networked filesystems.** NFS `fsync` semantics are
  weaker than local; the server may not have committed by the time
  the client returns. Document that state files must live on
  local-attached storage with strong fsync semantics.

---

## Part 2 — The POSIX Recipe

This part is a self-contained reference for how to satisfy Part 1 on
POSIX. It is project-independent — every wolfSSL component that needs
durable atomic state persistence on Unix-like systems should follow
this recipe.

### 2.1 The atomic-rename pattern

The canonical POSIX recipe for "atomic durable replace of a file" is:

```text
1.  fd_t = open temp file (mkstemp + fchmod)        # exclusive, mode 0600
2.  write all bytes to fd_t                          # data → page cache
3.  fflush(fd_t)                                     # stdio buffer → kernel
4.  fsync(fd_t)                                      # page cache → disk
5.  close(fd_t)
6.  rename(temp_path, final_path)                    # atomic on same FS
7.  fd_d = open parent directory, O_RDONLY|O_DIRECTORY
8.  fsync(fd_d)                                      # dirent → disk
9.  close(fd_d)
```

Every step exists to defend against a specific failure mode. Skipping
any of them creates a window where a crash leaves the system in an
unsafe state.

### 2.2 Why each step

**`mkstemp` for the temp file.** Random-named temp files defeat
symlink-in-the-temp-slot attacks, and `mkstemp` opens with `O_CREAT |
O_EXCL` so the open fails if the path exists. The temp file MUST live
in the same directory as the final file — `rename()` is atomic only
within a single filesystem.

**`fchmod 0600`.** State files contain private-key material. On glibc
`mkstemp` already creates with 0600; on older or non-glibc libcs the
mode is umask-derived (typically 0666 → 0644 after umask 022). Explicit
fchmod is the portable defense.

**`fflush()`.** The application typically uses stdio (`FILE*`). The
write path is `fwrite()` → stdio buffer → `write()` syscall → kernel
page cache. `fflush` walks the first hop; without it the userspace
buffer can still hold bytes when we call `fsync(fileno(fp))`.

**`fsync(fd_t)`.** This is the durability primitive. `close()` does not
imply data has reached stable storage; the Linux page-cache writeback
runs lazily (default `dirty_writeback_centisecs = 500` = 5 seconds
between background passes, but data is held for up to
`dirty_expire_centisecs = 3000` = 30 seconds before being forced out).
`fsync` blocks until the data is on the platter / NAND, including the
disk's internal volatile cache (the syscall issues a SCSI/ATA
`FLUSH CACHE` to the device).

If `fsync` returns an error, the right response is to **abort the
commit** (unlink the temp, return failure). Past Linux versions had
buggy `fsync` semantics that "consumed" the error on a single fd, so
later fsyncs returned success even though writeback had failed
("fsyncgate", 2018). Modern Linux returns the error on every fd that
shared the bad page, so the right policy is unchanged: propagate.

**`rename(temp, final)`.** POSIX guarantees that `rename` is atomic
within a single filesystem: any concurrent `open(final)` either sees
the old inode or the new one, never both nor neither. This is the
"all-or-nothing" leg of atomicity.

Importantly, on success the kernel's directory state now points at the
new inode and the temp name no longer exists. On failure, both the
temp and the final still exist; the temp must be unlinked by the
caller.

**`fsync(dir_fd)`.** This is the leg most often skipped, and it is
mandatory. The rename updated the directory entry in the parent
inode's data; that update is itself a write that may sit in the page
cache. A power loss after `rename()` returns but before the directory
metadata reaches disk can roll the rename back. On journaled
filesystems mounted with default barrier semantics (ext4 default, xfs
default, btrfs default), the journal usually orders the rename's
metadata together with the file's data, so a crash leaves a consistent
state — but the *exact* consistent state depends on the mount options.
On a filesystem mounted with `barrier=0` or on a non-journaling
filesystem (vFAT, FAT32 SD cards, some embedded NAND filesystems), the
parent fsync is the only thing that prevents rename rollback.

Treat `fsync(dir_fd)` as mandatory; the cost (one extra fsync per
sign) is small compared to the cost of OTS-key reuse.

The `fsync(dir_fd)` call may legitimately fail with `EINVAL` on
filesystems that do not implement directory fsync (some legacy /
embedded filesystems). That single errno is the only one to tolerate;
every other errno should be treated as a durability failure.

### 2.3 What `O_TRUNC` cannot do

A naive implementation `open(final, O_WRONLY|O_TRUNC); write(); close()`
fails atomicity outright. `O_TRUNC` truncates the file to zero before
the write. A crash between the truncate and the write leaves the file
empty. There is no time at which the file contains the *previous*
state — it always contains either zero bytes or the new state.

For a stateful HBS state file this means: on a crash, the leaf counter
on disk is gone. The application either treats "empty file" as
"unloadable key" (best case: the key is bricked, but no leaf reuse),
or — catastrophically — re-initializes from scratch (leaf reuse from
zero).

The temp-and-rename pattern preserves the previous state across a
crash. That is the entire point.

### 2.4 Read path

Read is structurally simpler:

```text
1.  fd = open(final, O_RDONLY)
2.  read all bytes
3.  validate AEAD tag
4.  close(fd)
```

The read path does not fsync. The only POSIX-level concern is that
`open(final)` returns the file that the last successful `rename`
produced — which is the kernel's guarantee. Concurrent writers using
the same atomic-rename pattern do not corrupt readers; at worst, two
sequential reads return two different consistent files.

### 2.5 Concurrency primitives

Within a single process, an `fcntl(F_SETLKW)` advisory lock or a
process-internal mutex serializes signers.

Across processes, POSIX offers two options:

- **`flock(LOCK_EX | LOCK_NB)`** on a sentinel file in the token
  directory. Advisory, BSD origin. Released on process death (kernel
  closes the fd → flock dropped). Works on local filesystems; weak
  on NFS.
- **`fcntl(F_SETLK)`** byte-range locks. POSIX-mandated, also released
  on process death. Famously gnarly semantics around `close()` (any
  close on any fd referring to the file drops all locks held by the
  process on that file) and on NFS (varies by server).

Neither is foolproof on shared storage. Cross-host coordination
requires a higher-layer service.

### 2.6 What POSIX explicitly does NOT give

- **Anti-rollback at the FS level.** A privileged copy of the file is
  forever indistinguishable from the original. Defenses live above
  POSIX (TPM, attestation, dedicated NV counters).

- **Fork detection.** `pthread_atfork` is the application-level hook;
  no syscall fires "parent forked you" to the child.

- **VM snapshot detection.** The hypervisor is invisible to POSIX.

- **Durable fsync over a network filesystem.** NFS fsync semantics
  vary; CIFS even more. Hard requirement: state files on
  local-attached storage.

### 2.7 The skeleton

A POSIX-only "write encrypted state durably" routine, in pseudo-code:

```c
int durable_atomic_write(const char* final_path,
                         const byte* data, size_t len)
{
    char tmpl[PATH_MAX];
    snprintf(tmpl, sizeof tmpl, "%s.tmpXXXXXX", final_path);
    int fd = mkstemp(tmpl);
    if (fd < 0) return -1;
    if (fchmod(fd, 0600) != 0)                       goto fail;

    if (write_all(fd, data, len) != (ssize_t)len)    goto fail;
    if (fsync(fd) != 0)                              goto fail;
    if (close(fd) != 0) { fd = -1;                   goto fail; }
    fd = -1;

    if (rename(tmpl, final_path) != 0)               goto fail;

    int dfd = open(dirname_of(final_path),
                   O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0)                                     return -1;
    if (fsync(dfd) != 0 && errno != EINVAL) {
        close(dfd);                                  return -1;
    }
    close(dfd);
    return 0;

fail:
    if (fd >= 0) close(fd);
    unlink(tmpl);
    return -1;
}
```

That is the entire POSIX side of Part 1, in 25 lines.

---

## Part 3 — wolfPKCS11 Realisation

This part shows how the contract (Part 1) and the POSIX recipe (Part 2)
are implemented inside wolfPKCS11. The structure follows the same
seven-property breakdown as Part 1, with file/function references.

### 3.1 Identity: the per-key 64-bit nonce

Every stateful-sig private key has an opaque `statefulStateId` field
(`WP11_Object::statefulStateId`, `word64`) generated at keygen:

```c
WP11_Hss_GenerateKeyPair():        /* src/internal.c */
    byte nonceBuf[8];
    for (tries = 0; tries < 4; tries++) {
        WP11_Slot_GenerateRandom(slot, nonceBuf, 8);
        priv->statefulStateId = wp11_Stateful_ReadU64(nonceBuf);
        if (priv->statefulStateId != 0) break;
    }
```

It is:

- Random (RNG-sourced, 64-bit, rejecting zero so we have an
  "uninitialised" sentinel).
- Persisted as the **last 8 bytes** of the shell file. This trailer
  convention is a framework invariant (see `wp11_Stateful_PeekStateIdFromShell`
  in §3.6) — every stateful-sig scheme respects it.
- Used to key the state file path (next section), independent of the
  object's position in the token list — solving the "renumbering"
  hazard from Part 1, §1.4.

### 3.2 File naming: word64-safe path

State files live at:

```
<token_dir>/wp11_<scheme>_priv_state_<tokenId>_<statefulStateId>
                                      ^^^^^^^^^  ^^^^^^^^^^^^^^^^
                                      %016lx     %016llx
```

The path-builder is `wp11_Stateful_StateFile_Path()` in `src/internal.c`.
The `%016llx` cast (`unsigned long long`) is mandatory: `CK_ULONG` is
32-bit on LLP64 platforms (Windows) and would otherwise truncate the
nonce to 32 bits, shrinking the birthday-bound collision space from
2^32 keys to 2^16. The public wolfPKCS11 storage API (`wolfPKCS11_Store_Open`
in `wolfpkcs11/store.h`) uses `CK_ULONG` and is *not* used for state
files; the path-builder above is the only entry point.

### 3.3 Atomic write: `WP11_FileStoreCtx` + `mkstemp` + `rename`

The storage layer maintains a per-open context:

```c
typedef struct WP11_FileStoreCtx {       /* src/internal.c:~1116 */
    XFILE  file;
    int    is_write;
    int    has_temp;
    int    durable;
    char   final_name[WP11_STORE_MAX_PATH];
    char   temp_name [WP11_STORE_MAX_PATH];
} WP11_FileStoreCtx;
```

The lifecycle of a write:

| Step | Function | What it does |
|------|----------|--------------|
| open | `wp11_Stateful_StateFile_Open(read=0)` | builds the final path, allocates ctx, calls `wolfPKCS11_StoreCreateTempFile` which runs `mkstemp` next to the final path |
| write | `wp11_storage_write` | `XFWRITE` into the stdio buffer |
| commit | `wolfPKCS11_Store_CloseAndReport` | `XFFLUSH` → `fsync(fileno)` → `XFCLOSE` → `wolfPKCS11_StoreCommitTemp` |
| commit-rename | `wolfPKCS11_StoreCommitTemp` | POSIX `rename(temp, final)` + `fsync(parent_dir)` |
| abort | `wolfPKCS11_StoreAbortTemp` | `remove(temp)` on any error |

The `durable` flag in the ctx gates the two fsyncs. It is set by
`wolfPKCS11_Store_SetDurable(storage, 1)` from `wp11_Stateful_WriteStateBlob`
whenever `wp11_StatefulShouldFsync()` returns 1 (always, unless
`WOLFPKCS11_STATEFUL_RELAX_FSYNC=1`).

`wolfPKCS11_Store_CloseAndReport` returns non-zero if either fsync or
rename failed. The framework propagates this all the way back to
wolfCrypt's write CB as `WC_LMS_RC_WRITE_FAIL`, which causes wolfCrypt
to abort the sign — closing the loop on Part 1, §1.1.

### 3.4 The AAD-bound encryption layer

Encryption is AES-GCM under the slot's master key
(`o->slot->token.key`, derived from the user PIN via scrypt + HKDF).
The framework writer is `wp11_Stateful_WriteStateBlob` in `src/internal.c`.

Header layout (the AAD):

```text
offset  length  field
------  ------  -----
   0     u32    magic            (scheme-specific: HSS = "HSSS")
   4     u32    version          (current: 2)
   8     u32    schemeParamLen   (scheme-specific: HSS = 12)
  12     P      schemeParamBytes (HSS = levels|height|winternitz)
  12+P   u64    statefulSigCount (running signature counter)
```

Followed by the file body:

```text
[u32 ivLen][iv (12 B)][u32 ctLen][ciphertext (privSz + 16-byte GCM tag)]
```

`schemeParamLen` in the AAD serves a diagnostic purpose: a thin-wrapper
that mis-passes the param length surfaces as a clean `BAD_FUNC_ARG`
before AES-GCM decrypt, rather than as opaque tag failure (which would
look like file corruption).

`statefulSigCount` in the AAD is what gives the framework
*counter-rollback detection within the AEAD*. A bit flip in the
on-disk counter fails the tag; an explicit AAD-side rewrite by an
attacker who knows the slot key fails because they don't have the
GCM authenticator without re-encrypting the whole file (and that
requires the slot key, which lives encrypted under the PIN).

It does **not** prevent file-level rollback (substituting an older
intact file) — see Part 1, §1.6.

### 3.5 Reading the state

`wp11_Stateful_ReadStateBlob` performs the symmetric operation. The
order is critical:

```c
1.  open file (read-only)
2.  read [hdr][ivLen|iv][ctLen|ct||tag]
3.  validate magic, version, schemeParamLen, schemeParams against expected
4.  wp11_DecryptDataAAD(...)  → verifies tag, decrypts
5.  on success: restore statefulSigCount from the persisted AAD
6.  on any failure: wc_ForceZero(priv, privSz) and return error
```

Step 3 is "validate before decrypt" — `BAD_FUNC_ARG` for a
header-mismatch is faster and more diagnostic than letting the AEAD
catch it. Step 6 is non-negotiable: a caller relying on the "zero on
failure" contract (Part 1, §1.3.3) must not be handed garbage.

### 3.6 Shell file and the trailer convention

A second on-disk file per private key — the **shell** — carries
non-secret metadata (parameter set, cached public key, and the
`statefulStateId` trailer):

```text
[u32 magic][u32 version][scheme-specific bytes ... pub bytes][u64 stateId]
```

The shell is written by the regular wolfPKCS11 storage path
(`wolfPKCS11_Store_Open`) and is keyed by the object's position in the
token list — *because* the position changes when other objects are
added or removed, but the shell rewrites itself in lockstep with that
re-numbering.

The state file path uses the nonce. To bridge between the two on
operations like `C_DestroyObject` (which only has the object's list
position, not the in-memory key), we need to find the nonce from the
shell. The framework helper:

```c
wp11_Stateful_PeekStateIdFromShell(tokenId, objId, storeTypeShell,
                                   expectedShellMagic, expectedShellVersion,
                                   &outStateId);
```

reads the shell, validates its magic+version (refuses to return a
nonce from a corrupted or wrong-scheme file), and returns the last 8
bytes. The trailer convention is the framework's **only** abstraction
over scheme-specific shell layouts: every scheme writes its nonce at
the end, so peek is scheme-agnostic given the magic check.

### 3.7 Concurrency: the token lock

Sign acquires the token lock unconditionally:

```c
WP11_Hss_Sign() {                       /* src/internal.c */
    WP11_Lock_LockRW(priv->lock);       /* priv->lock = &token->lock */
    ...
    wc_LmsKey_Sign(...);                /* fires write CB inside */
    ...
    WP11_Lock_UnlockRW(priv->lock);
}
```

The token lock serialises sign vs. sign and sign vs. reload. The RNG
lock (`token->rngLock`, taken inside the write CB to generate fresh
GCM IVs) is acquired *under* the token lock — that ordering is
maintained everywhere to prevent deadlock.

The keygen path is an explicit exception (Part 1, §1.2.6 still
holds, but the locking layer differs): `WP11_Hss_GenerateKeyPair`
runs before the object is registered with the session, so no other
thread has a handle, and `priv->lock` is still NULL. The write CB
fires unlocked. This is safe because the in-memory key is
thread-local until `WP11_Session_AddObject` returns.

Cross-process serialisation is **not** implemented. wolfPKCS11
documents that the token directory must not be shared between
concurrent processes; in practice a future `flock()` on a sentinel
file in the token dir would close this.

### 3.8 Failure handling: the poison flag

`WP11_FLAG_STATEFUL_STATE_VALID` in `WP11_Object::opFlag`:

- **Set** by `WP11_Hss_GenerateKeyPair` after a successful keygen, and
  by `wp11_Object_Decode_HssKey` after a successful Reload.
- **Cleared** by `WP11_Hss_Sign` on any wolfCrypt error (which covers
  both "write CB failed" and "key exhausted" — wolfCrypt does not
  distinguish, and neither outcome is safe to sign against in
  memory).
- **Cleared** by `wp11_Object_Decode_HssKey` on Decode failure, in
  case `opFlag` was restored from disk with the bit set from a prior
  successful run.

When clear, `WP11_Hss_Sign` returns `NOT_AVAILABLE_E` → `CKR_DEVICE_ERROR`.
The application's recovery is to `C_Finalize` / `C_Initialize`, which
re-loads the object from disk via Decode → wolfCrypt Reload → our
read CB → fresh durable state in memory. The poison clears.

### 3.9 Orphan cleanup

A state file with no in-memory key referencing it is an orphan. There
are three orphan-creating paths, and each has explicit handling:

1. **Keygen succeeds, AddObject fails.**
   - `WP11_Session_AddObject` (`src/internal.c:9651`) rolls back the
     linked-list insertion if `wp11_Slot_Store` fails after linking,
     resetting `object->handle` to `CK_INVALID_HANDLE`.
   - `WP11_Object_Free` then sees
     `handle == CK_INVALID_HANDLE && statefulStateId != 0` and calls
     `wp11_Stateful_StateFile_Remove("hsskey", ...)`.

2. **Keygen partially fails (MakeKey succeeded but a later step
   inside `WP11_Hss_GenerateKeyPair` failed).** The function's
   rollback block calls `wp11_Stateful_StateFile_Remove` explicitly
   before returning.

3. **`C_DestroyObject` on a token HSS key.**
   `wp11_Object_Unstore` recovers the stateId from the in-memory
   object (or by Peek-ing the shell if not decoded yet) and calls
   `wp11_Stateful_StateFile_Remove`. The shell is removed by the
   regular Store_Remove path that runs alongside.

A 64-bit nonce makes the probability of a future keygen colliding
with an orphan negligible (2^-64), so even an orphan that escapes
cleanup is not a security risk — only disk-space waste.

### 3.10 The durability env-var

`WOLFPKCS11_STATEFUL_RELAX_FSYNC=1` skips both `fsync`s
(file and parent dir). It is opt-in, documented as non-production,
and prints a one-time prominent warning to stderr on first sign:

```c
wp11_StatefulShouldFsync() (resolved once during WP11_Library_Init):
    "wolfPKCS11: WARNING: WOLFPKCS11_STATEFUL_RELAX_FSYNC=1 is set..."
```

It exists for two reasons:

- Test harnesses backed by tmpfs (CI environments) where `fsync` is a
  no-op anyway but the syscall overhead is measurable.
- Documentation: forcing operators to encounter the warning when
  they enable it makes the production hazard explicit.

There is no per-key knob. Every scheme that joins the framework
shares the gate.

### 3.11 Scheme registration

A scheme plugs into the framework by providing:

- A scheme file prefix string (HSS = `"hsskey"`).
- Magic and version constants for shell and state.
- A scheme-params packer (`wp11_Hss_PackSchemeParams`: 3 × u32 →
  12 bytes).
- Thin write/read CB wrappers that translate wolfCrypt's enum
  return values to the framework's int returns.
- An encode/decode pair for the shell file that respects the
  "stateId trailer at last 8 bytes" convention.
- One case each in the `WP11_Object` union, the `C_GenerateKeyPair`
  switch (with on-token enforcement), and `wp11_Object_Unstore`.

Nothing else. The framework owns persistence, encryption, fsync,
rename, peek, orphan-cleanup, the env-var gate, and the poison
flag. The scheme owns its own params, callbacks, and PKCS#11
mechanism wiring.

---

## Applicability to other wolfSSL projects

Parts 1 and 2 of this document are **portable**. They are the
contract and the recipe; they describe what any layer wiring the
wolfCrypt LMS/XMSS callbacks must guarantee.

Part 3 describes one realisation, the one inside wolfPKCS11. A
different consumer — for example **wolfHSM** running on a constrained
embedded device — should be expected to:

- Honour every requirement in Part 1 to the same letter. The
  cryptographic invariant doesn't care about the host environment.
- Replace Part 2's POSIX recipe with the equivalent for its own
  storage medium. On flash-backed NV: emulate `mkstemp`-and-rename
  via dual banks + a commit-pointer write, where the commit-pointer
  write is the single atomic transition. On RTOS file systems
  (LittleFS, FatFs): they typically expose a `_sync()` analogue;
  use it. On TPM NV: the NV write itself is atomic; the discipline
  reduces to "increment counter, then write, then verify".
- Keep §3.x's structural choices that are not POSIX-specific —
  the per-key 64-bit nonce, the AAD-bound counter, the poison flag,
  the AAD layout with `schemeParamLen` — because those are properties
  of the abstraction, not of POSIX.

The lift to wolfHSM is therefore: re-implement Part 2 for the HSM's
NV layer, lift §3.4–§3.10 mostly unchanged, re-derive identity
(§3.1) and naming (§3.2) in whatever terms the HSM's storage allows.
The wolfCrypt callback shapes (Part 1, §1.1) are identical because
wolfCrypt is the shared dependency.
