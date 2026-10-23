# Linux emergency distrust mechanisms

Research snapshot: 2026-10-23. This note supports implementing the existing `fix` flow on Linux. It records native trust-store mechanisms; no system changes were applied during research.

## Native providers

| Family | Source of local policy | Regeneration | TLS bundle to inspect |
|---|---|---|---|
| Debian / Ubuntu | `/etc/ca-certificates.conf` deselection entries | `/usr/sbin/update-ca-certificates` | `/etc/ssl/certs/ca-certificates.crt` |
| Alpine with full `ca-certificates` | `/etc/ca-certificates.conf` deselection entries | `/usr/sbin/update-ca-certificates` | `/etc/ssl/certs/ca-certificates.crt` |
| Fedora / RHEL | `/etc/pki/ca-trust/source/blocklist/` (older installations: `blacklist/`) | `/usr/bin/update-ca-trust extract` | `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem` |
| Arch | `/etc/ca-certificates/trust-source/blocklist/` | `/usr/bin/update-ca-trust extract` | `/etc/ca-certificates/extracted/tls-ca-bundle.pem` |
| openSUSE / SLES | `/etc/pki/trust/blocklist/` (older installations: `blacklist/`) | `update-ca-certificates` | Generated under `/var/lib/ca-certificates`; legacy `/etc/ssl/ca-bundle.pem` is an alias |

The mechanisms and historical directory fallback are documented by the incident's upstream workaround. Debian, Alpine, Fedora and Arch package inventories independently establish the absolute updater paths above. For openSUSE, inspect the installed package rather than infer an executable location from its command name. [Incident workaround](https://emudhra.we-have-a-problem.com/#workarounds), [Debian inventory](https://packages.debian.org/trixie/all/ca-certificates/filelist), [Alpine inventory](https://pkgs.alpinelinux.org/contents?arch=loongarch64&branch=v3.22&name=ca-certificates&repo=main), [Fedora inventory](https://packages.fedoraproject.org/pkgs/ca-certificates/ca-certificates/fedora-43.html), [Arch inventory](https://archlinux.org/packages/core/any/ca-certificates-utils/files/)

This is capability detection, not just distribution-name detection: check the policy inputs, updater, expected output, and file ownership before constructing a plan. Keep the initial supported families explicit; reject unknown layouts instead of editing whichever `cert.pem` happens to exist.

## Debian and Ubuntu

Prefix an enabled distribution certificate entry with `!` to deactivate it. Paths in `/etc/ca-certificates.conf` are relative to `/usr/share/ca-certificates`. Local `.crt` files under `/usr/local/share/ca-certificates` are included independently and implicitly trusted. The updater builds the PEM bundle and individual certificate collection; it invokes hooks in `/etc/ca-certificates/update.d` with added/removed certificate paths. `--fresh` removes generated symlinks. [Debian manual](https://manpages.debian.org/testing/ca-certificates/update-ca-certificates.8.en.html)

The advisory names `mozilla/emSign_ECC_Root_CA_-_G3.crt` and `mozilla/Comodo_AAA_Services_root.crt`; identify certificates by the pinned DER fingerprints from [the macOS research](macos-emergency-fix.md), not filenames alone. Its Java caveat recommends a fresh `ca-certificates-java` rebuild when stores diverge. [Incident workaround](https://emudhra.we-have-a-problem.com/#workarounds)

Implementation implications:

- Parse every enabled source and local certificate. Disabling one distribution path does not remove another trusted copy of the same root.
- Preserve unrelated configuration. For a first implementation, refuse an ambiguous/local duplicate with its exact path before any mutation; alternatively implement an explicit, journaled quarantine for that file. Never silently report success while a duplicate survives.
- Store exact before/after configuration bytes and hashes. Refuse undo after configuration drift unless a deliberate merge can prove it changes only emBarrass-owned entries. Do not reintroduce entries removed or disabled by a vendor update.
- Run regeneration after apply and rollback. A successful PEM check alone does not certify independent Java stores or application-private stores; report coverage precisely.

## Alpine

Alpine packages distinguish `ca-certificates` from `ca-certificates-bundle`. The latter owns the generated PEM bundle and `/etc/ssl/cert.pem` symlink to `certs/ca-certificates.crt`. The full package generates `/etc/ca-certificates.conf`, installs the updater, and installs a `certhash` hook that runs `/usr/bin/c_rehash /etc/ssl/certs`. Package triggers watch certificate and hook directories. [Alpine package source](https://raw.githubusercontent.com/alpinelinux/aports/master/main/ca-certificates/APKBUILD)

Minimal images can therefore have a usable TLS bundle without the policy/regeneration machinery. Treat that as a missing prerequisite; do not pretend the Debian-style provider is available. Current upstream GitLab implementation source was inaccessible during this review, so validate actual updater behavior in the target Alpine container, including local duplicates, idempotency, symlink regeneration, and hook failures.

## Fedora and RHEL: explicit local distrust

Red Hat documents `/etc/pki/ca-trust/source/blocklist/` as the administrator distrust directory, with higher-priority policy than the vendor's `/usr/share/pki/ca-trust-source/`. `update-ca-trust extract` updates the shared store used by supported NSS, GnuTLS, OpenSSL and Java consumers. [RHEL trust-store documentation](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/securing_networks/using-shared-system-certificates_securing-networks)

p11-kit treats certificates in its `blocklist/` directory as distrusted even without embedded trust flags. Merely placing a normal PEM in the parent directory gives neutral policy, and an `anchors/` directory gives positive trust. [p11-kit trust module](https://p11-glue.github.io/p11-glue/p11-kit/manual/trust-module.html)

Create unique, emBarrass-owned PEM files containing the two verified target roots in the local distrust directory, then regenerate. Do not overwrite similarly named files already owned by an administrator or package. This avoids editing the vendor bundle and makes undo narrow: remove only files created by the recorded transaction after verifying their hashes, then regenerate from current vendor policy. A vendor update applied after the repair is naturally preserved.

Legacy paths may be symlinks to generated output. Fedora's package history explicitly records changes and restoration of aliases such as `/etc/ssl/cert.pem` and `/etc/pki/tls/certs/ca-bundle.crt`. Verify the installed layout; do not replace aliases with regular files. [Fedora package history](https://packages.fedoraproject.org/pkgs/ca-certificates/ca-certificates/fedora-43.html)

## Arch and openSUSE differences

Arch provides the same broad policy model at different paths. Its manual explicitly says generated outputs must not be edited. Simple PEM and Java output omit distrusted roots; the extended OpenSSL bundle may retain certificates with rejection flags. Therefore a certificate's presence in the extended bundle is not evidence of positive trust. `/etc/ssl/cert.pem`, legacy bundle aliases, Java aliases, and hashed certificates refer to generated output. [Arch manual](https://man.archlinux.org/man/update-ca-trust.8.en)

openSUSE's source says `/etc/ca-certificates.conf` is unsupported. p11-kit policy under `/etc/pki/trust` drives generated stores, and every store is produced by hooks. Its updater processes `.run` hooks under `/etc/ca-certificates/update.d` and `/usr/lib/ca-certificates/update.d`; this differs from Debian despite sharing the command name. [openSUSE README](https://raw.githubusercontent.com/openSUSE/ca-certificates/master/README), [updater source](https://raw.githubusercontent.com/openSUSE/ca-certificates/master/update-ca-certificates)

## Transaction and verification recommendations

These are engineering recommendations:

1. Pin certificate identity, inventory all applicable source inputs, and preflight the entire plan before changing anything.
2. Execute only the known root-owned regeneration tool with a controlled environment and PATH. Its administrator-installed hooks remain part of the native update operation; capture their output and failures.
3. Journal source changes before applying them. Native regeneration updates multiple files and hooks; do not describe the whole transaction as atomic.
4. Validate generated TLS anchors and the hashed-directory view; do not parse an extended trust bundle as an ordinary positive-only bundle. Preserve unrelated trust and enterprise roots.
5. On regeneration/integrity failure, undo only owned source changes and regenerate again. If recovery fails, retain the journal and report the incomplete state rather than success.
6. Undo must regenerate from current sources, never copy an old generated bundle over a later vendor update. A drift refusal is preferable to guessing ownership.
7. Keep filesystem repair status separate from actual client tests. Run both emSign and AAA paths unprivileged, and report independently configured tools or containers separately.

This emergency patch remains compatible with recommending normal vendor updates. Its immediate job is to apply native local distrust wherever the required policy and regeneration machinery already exists.

## Implementation validation

On 2026-10-23, `pkg/repair/testdata/native-smoke.sh` passed in disposable arm64
containers built from these official image digests:

- Debian bookworm-slim: `sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8`
- Alpine: `sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a`
- Fedora: `sha256:43b29f65a41eb9c35e1cd5323e3bdf3b655c2357a9f4f1ff2f9c2798e5045d80`

The images install current native CA tools, curl, OpenSSL, and `su`; they seed
public vulnerable roots solely inside the container. Tests run without external
network access or host mounts. They verify a read-only preview, native repair,
both forged paths through curl's default store, the unprivileged `fix` verdict,
preservation of an unrelated enterprise root, no-op inspection, and undo.
Fedora additionally retains a simulated vendor distrust update across undo.
Ubuntu and the RHEL derivatives were not separately exercised.

These tests exposed two verification details. The runner must wait for active
TLS handlers after child exit instead of draining their observations early.
Also, the newer Alpine and Fedora curl builds completed the handshake before
exiting 60 and resetting the connection without a TLS rejection alert. The
generic wrapper correctly leaves that case inconclusive; the controlled `fix`
probe can combine observed tunnel traffic with curl's explicit peer-verification
exit code. Generic TLS errors, unobserved failures, and timeouts remain
inconclusive. [curl error-code documentation](https://curl.se/libcurl/c/libcurl-errors.html)

The full Go race-enabled suite and lint passed. macOS was checked with a
read-only system dry run and temporary-bundle tests; no host trust changes were
applied during this validation.
