#!/bin/sh
# Copyright (C) 2026 boostsecurity.io
# SPDX-License-Identifier: GPL-3.0-or-later
# Destructive only inside an explicitly opted-in disposable test container.
set -eu
test "${EMBARASS_FIX_TEST:-}" = disposable-container
test -f /.dockerenv || test -f /run/.containerenv
test "$(id -u)" = 0

BIN=/fixtures/embarass
. /etc/os-release
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj /CN=emBarrass-Test-Enterprise-Root \
  -keyout /tmp/enterprise.key -out /tmp/enterprise.crt >/dev/null 2>&1

case "$ID" in
  debian|ubuntu|alpine)
    mkdir -p /usr/share/ca-certificates/embarass-test /usr/local/share/ca-certificates
    cp /fixtures/aaa.pem /usr/share/ca-certificates/embarass-test/aaa.crt
    cp /fixtures/emsign.pem /usr/share/ca-certificates/embarass-test/emsign.crt
    cp /tmp/enterprise.crt /usr/local/share/ca-certificates/enterprise.crt
    printf '# disposable test fixture\nembarass-test/aaa.crt\nembarass-test/emsign.crt\n' > /etc/ca-certificates.conf
    /usr/sbin/update-ca-certificates --fresh >/tmp/seed.log 2>&1
    BUNDLE=/etc/ssl/certs/ca-certificates.crt
    ;;
  fedora|rhel)
    # Isolate the seed from the current vendor's existing eMudhra distrust.
    mv /usr/share/pki/ca-trust-source /tmp/original-vendor-ca-source
    mkdir -p /usr/share/pki/ca-trust-source /etc/pki/ca-trust/source/anchors /etc/pki/ca-trust/source/blocklist
    cp /fixtures/aaa.pem /etc/pki/ca-trust/source/anchors/aaa.pem
    cp /fixtures/emsign.pem /etc/pki/ca-trust/source/anchors/emsign.pem
    cp /tmp/enterprise.crt /etc/pki/ca-trust/source/anchors/enterprise.pem
    /usr/bin/update-ca-trust extract >/tmp/seed.log 2>&1
    BUNDLE=/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
    ;;
  *) echo "Unsupported smoke-test container: $ID"; exit 2 ;;
esac

probe() {
  want=$1
  for chain in emsign sectigo; do
    set +e
    "$BIN" --headless --chain "$chain" -- /usr/bin/curl -q --silent --output /dev/null \
      --max-time 5 https://example.com/ >/tmp/probe.log 2>&1
    actual=$?
    set -e
    # The generic wrapper cannot interpret arbitrary child exit codes. Newer
    # curl can finish TLS then fail certificate verification without an alert.
    if test "$want" = 0 && test "$actual" = 2 &&
       grep -q 'child_exit_code=60' /tmp/probe.log &&
       grep -q 'reason=no_tls_decision' /tmp/probe.log; then
      actual=0
    fi
    if test "$actual" != "$want"; then
      cat /tmp/probe.log
      echo "$ID $chain: expected exit $want, got $actual"
      exit 1
    fi
  done
}

apply() {
  set +e
  "$BIN" fix --yes --headless >/tmp/fix.log 2>&1
  result=$?
  set -e
  # Root application intentionally leaves behavioral verification to the caller.
  if test "$result" != 2 || ! grep -q 'REGENERATED' /tmp/fix.log; then
    cat /tmp/fix.log
    exit 1
  fi
}

probe 1
before=$(sha256sum "$BUNDLE")
"$BIN" fix --dry-run --headless >/tmp/preview.log 2>&1
test "$before" = "$(sha256sum "$BUNDLE")"
apply
probe 0
su -s /bin/sh nobody -c "$BIN fix --yes --headless" >/tmp/unprivileged-fix.log 2>&1 || {
  cat /tmp/unprivileged-fix.log
  exit 1
}
grep -q 'BOTH FORGERIES REJECTED' /tmp/unprivileged-fix.log
openssl verify -CAfile "$BUNDLE" /tmp/enterprise.crt
"$BIN" fix --dry-run --headless >/tmp/noop.log 2>&1
grep -q 'TARGET ROOTS ALREADY ABSENT' /tmp/noop.log
"$BIN" fix --undo --yes --headless >/tmp/undo.log 2>&1
probe 1

if test "$ID" = fedora || test "$ID" = rhel; then
  apply
  cat /fixtures/aaa.pem /fixtures/emsign.pem > /etc/pki/ca-trust/source/blocklist/vendor-update.pem
  /usr/bin/update-ca-trust extract
  "$BIN" fix --undo --yes --headless >/tmp/undo-vendor.log 2>&1
  test -f /etc/pki/ca-trust/source/blocklist/vendor-update.pem
  probe 0
fi
echo "PASS $ID: preview, native repair, both trust paths, enterprise root, undo"
