# macOS emergency trust-bundle repair

Research snapshot: 2026-10-23. This is a source review and proposed design, not an applied system repair.

## Current vendor status and platform scope

Rechecked 2026-10-23: the live incident advisory dates Apple's intermediate blocking to October 22, while still explicitly describing `/etc/ssl/cert.pem` as unpatched. Those are separate mechanisms; native trust mitigation does not establish that the PEM bundle changed. [Live advisory](https://emudhra.we-have-a-problem.com/)

Apple's current security-release index lists macOS 27.0.1, 26.7.1, and 15.8.1 releases dated September 28. Apple also documents security configuration and system-data updates between OS releases. Therefore the release dates alone cannot establish whether a fix reached every device. No Apple-issued notice confirming an eMudhra update to `/etc/ssl/cert.pem` was found in this review. The local file observation below establishes only this Mac's contents. [Apple security releases](https://support.apple.com/en-us/100100), [Apple background updates](https://support.apple.com/en-us/101591)

Native Apple trust also needs careful wording. Upstream issue #69 records incomplete rejection on October 21–22, then multiple October 23 reports of all test chains being rejected without local changes. Reporters associate the improvement with the OCSP responder recovering and question whether blocking is unconditional. Separately, the advisory maintainer explains that CT would exclude the reported non-test-domain certificates from Apple browser trust, and that Apple-trusted CT logs had stopped accepting these intermediates by October 21. These observations concern different layers; they do not prove general Safari exploitability or a PEM-file fix. Treat the issue as evolving evidence and test the actual client. [Upstream issue #69, including October 23 updates](https://github.com/galadran/we-have-a-problem.com/issues/69)

Linux already has vendor package fixes. These are verified examples, not an exhaustive supported-version matrix:

| Platform | Current primary-source evidence | Preferred remediation mechanism |
|---|---|---|
| Debian | The issue records `20260816+nmu1` and `20250419+deb13u1`, blacklisting the two roots. [Debian bug #1151413](https://bugs.debian.org/1151413) | Upgrade the distribution's `ca-certificates` package. |
| Alpine | Its package index lists `20261020-r0`. [Alpine package index](https://pkgs.alpinelinux.org/packages?name=ca-certificates&arch=) | Upgrade `ca-certificates` in each affected image/system. |
| RHEL 9 | The vendor erratum supplies `2026.2.92_v9.0.319-90.3.el9_8`. [RHSA-2026:88459](https://access.redhat.com/errata/RHSA-2026:88459) | Install the applicable supported release's vendor update. |
| Arch | The live repository now lists `ca-certificates-mozilla` `3.132-1`, newer than the incident's initial fixed version. [Arch package page](https://archlinux.org/packages/core/x86_64/ca-certificates-mozilla/) | Update through the distribution's normal package workflow. |
| Ubuntu | The incident advisory lists fixed `ca-certificates` versions for 22.04, 24.04, 26.04, and 26.10; its linked Launchpad evidence was inaccessible during this review. [Advisory version table](https://emudhra.we-have-a-problem.com/#who-has-patched) | Use the distribution package update; verify the installed version and behavior. |

Engineering recommendation: share the diagnosis and plan interface across platforms, but use separate remediation providers. macOS needs this narrowly scoped emergency bundle edit; Linux should prefer vendor package updates, which own bundle generation and other store integration. Do not directly edit a generated Linux PEM bundle as a universal fix. Images, runtime-embedded roots, and user-specific bundles remain distinct repair targets. A host package update cannot be treated as proof that every container or application changed.

## What WardLatch does

WardLatch implements the advisory's macOS workaround: remove `AAA Certificate Services` and `emSign ECC Root CA - G3` from `/etc/ssl/cert.pem`. The advisory identifies this file as the separate trust source for Apple's built-in curl, git, Python, Perl, Ruby, and OpenSSL. It also publishes distinct direct and AAA-cross-signed test endpoints; checking one path does not exercise the other. [Original advisory](https://emudhra.we-have-a-problem.com/#are-there-workarounds-until-patches-are-available)

The upstream discussion records before/after measurements on macOS 26.7.1 for curl, git, Python, and OpenSSL, with nscurl as the system-trust comparison. Filippo Valsorda's merged October 21 change expanded the advisory and documented Apple's pip distinction. These sources establish the workaround's scope more directly than WardLatch's marketing page. [Issue #45](https://github.com/galadran/we-have-a-problem.com/issues/45), [PR #52](https://github.com/galadran/we-have-a-problem.com/pull/52)

The reviewed script:

- Requires Darwin and a file containing at least 50 certificate markers.
- Matches Apple-format comment headers by CN, then removes the corresponding sections using awk.
- Checks marker counts and absence of matching headers, without parsing certificates.
- Creates a timestamped `cp -p` backup after checking the name is unused.
- Copies the temporary output over the live file with `cp`, then sets mode 0644. This is not an atomic replacement.
- Tests only the direct DV-G3B endpoint with `/usr/bin/curl --cacert`.
- Restores the backup only when that test connects successfully. Other curl failures still produce a SAFE message qualified as unverified online.
- Has no rollback trap for write/chmod failure; its exit trap only deletes the temporary file.
- Provides a manual restore command and no-ops when matching headers are absent.

These are observations of source, not guarantees inferred from the landing page. [WardLatch script](https://github.com/deimos-hq/wardlatch/blob/main/fix/fix-macos.sh)

Its curl invocation also omits `-q`. curl documents that `-q` must be the first argument to suppress curlrc loading, so user configuration can affect this check. [curl manual](https://curl.se/docs/manpage.html#-q)

## Certificate identities

The advisory's machine-readable root inventory supplies these SHA-256 fingerprints of the complete DER certificate:

| Certificate | SHA-256(DER) |
|---|---|
| AAA Certificate Services | `D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4` |
| emSign ECC Root CA - G3 | `86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B` |

The inventory also includes `emSign Root TLS CA - G3` and `emSign Root CS CA - G3`, marked as not included in Apple's root store. Therefore these two removals are a specifically scoped Apple-bundle workaround, not a universal cleanup rule for arbitrary custom stores. [Root inventory](https://emudhra.we-have-a-problem.com/roots.json)

Local read-only observation on 2026-10-23: this workspace's Mac has 128 PEM certificates in `/etc/ssl/cert.pem`, including both exact fingerprints above. This establishes file contents, not the runtime vulnerability of any specific tool.

Removing trust anchors removes trust in every otherwise-valid path relying solely on those anchors, not just the compromised intermediate keys. This is an engineering consequence of root removal and should be visible in the proposed change summary.

## pip is a separate change

The advisory says Apple's built-in pip and environments created from Apple's Python use their own old root bundle. Its additional command appends Python code to `sitecustomize.py` to default `PIP_CERT` to `/etc/ssl/cert.pem`. This is separate from repairing the PEM file. [Original workaround](https://emudhra.we-have-a-problem.com/#are-there-workarounds-until-patches-are-available)

`sitecustomize` is Python startup customization, so editing it affects more than a single pip command. `PIP_CERT` is a documented pip bundle override. Prefer reporting this remaining exposure and handling it as an explicit, separately reversible action; do not silently append global startup code in the first bundle repair. [Python site documentation](https://docs.python.org/3/library/site.html#module-sitecustomize), [pip certificate configuration](https://pip.pypa.io/en/stable/topics/https-certificates/)

## Proposed emBarrass interface and requirements

These are design recommendations, not claims about WardLatch:

```text
embarass fix --dry-run   # show exact file, certificates, and affected scope
embarass fix             # show plan, confirm, apply, verify
embarass fix --yes       # apply the same plan noninteractively
embarass fix --undo      # restore a recorded repair with conflict detection
```

Keep `batch` as the behavioral check. `fix` clearly signals mutation; reserve `doctor` for diagnosis if broader environment analysis becomes necessary. Avoid promising that a bundle repair fixes every installed tool.

For the initial macOS implementation:

1. Parse PEM and X.509 certificates; identify removal targets by pinned certificate fingerprints. Preserve unrelated certificates and content, including enterprise roots. Reject malformed or ambiguous input.
2. Restrict writes to the known system bundle. Handle its resolved path deliberately; reject unexpected symlinks, ownership, or writable parent directories. Never run discovered PATH programs or Python startup hooks as root.
3. Create an exclusive backup and journal with original/replacement hashes and metadata. Stage on the same filesystem, validate the exact resulting certificate set, flush, then atomically replace. Detect concurrent modification before commit.
4. Separate file verification from behavioral verification. Exercise both trust paths using the existing local interception machinery and appropriate unprivileged clients. A patched Go verifier can reject compromised intermediates even with an unpatched bundle, so its rejection alone cannot validate this repair.
5. Report `applied`, `already applied`, `verification inconclusive`, and `still exposed` distinctly. An unrelated connection failure is not evidence of protection. If a file invariant fails, restore transactionally; do not silently undo a valid removal merely because one independently configured tool remains exposed.
6. Undo only when the current file still matches the recorded replacement, so a later vendor update or administrator edit is not overwritten. Explain that undo reintroduces the original trust anchors.
7. Re-run normal-user batch checks after the narrow repair and list remaining exposures with targeted next steps. Exclude the deliberately vulnerable historical Docker/Git fixture from host-repair success criteria. Updates may replace system files, so rechecking remains necessary.

The first release should repair only this known bundle. Separate runtime bundles, package upgrades, and global per-tool configuration need their own detection, review, and rollback contracts.
