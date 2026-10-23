# Public certificate fixtures

`aaa.pem` and `emsign.pem` are the exact public roots identified in the
[incident advisory's root inventory](https://emudhra.we-have-a-problem.com/roots.json).
Their pinned SHA-256 fingerprints are in `bundle.go`.

`legacy-negative-serial.pem` is Apple's existing EC-ACC root, extracted read-only
from `/etc/ssl/cert.pem` on October 23, 2026. It exercises compatibility with
legacy negative ASN.1 serial numbers. Tests require its bytes to survive repair
unchanged; it is not an eMudhra removal target.

These files contain public certificates only, not private keys. Enterprise
test roots are generated locally at test time.

`native-smoke.sh` exercises the native updater, both actual forged TLS paths,
enterprise-root preservation, and undo in Debian/Ubuntu/Alpine or Fedora/RHEL
containers. It deliberately replaces trust inputs to seed a vulnerable fixture.
It refuses to run unless root, inside a container, and explicitly opted in with
`EMBARASS_FIX_TEST=disposable-container`. Copy the Linux binary, this script, and
the two public roots into `/fixtures`; install native CA tools, curl, OpenSSL,
and `su` in the disposable image first. The test drops to `nobody` to verify
the actual repair command's verdict, so retain SETUID/SETGID capabilities.
Never run it against a production container.
