#!/usr/bin/env bash
# install.sh — make this machine trust the Telimatic internal root CA, so
# *.telimatic.internal sites open in Chrome and Safari without a warning.
#
#   macOS / Linux:  curl -fsSL https://get.telimatic.com/ca/install.sh | bash
#   remove it:      curl -fsSL https://get.telimatic.com/ca/install.sh | bash -s -- --uninstall
#   just look:      curl -fsSL https://get.telimatic.com/ca/install.sh | bash -s -- --show
#
# WHAT YOU ARE TRUSTING, IN ONE PARAGRAPH. This is a PUBLIC certificate — the CA's
# public half. The private key that signs with it lives only in Oracle Cloud
# vaults and is not in this script, this repository, or on any server. The
# certificate carries a CRITICAL X.509 name constraint permitting
# DNS:telimatic.internal and nothing else, which means a correct TLS client
# REJECTS anything this CA signs for any other name: it cannot vouch for
# google.com, your bank, or your employer's real domain. That constraint is what
# makes installing it on a personal machine reasonable. It is not nothing,
# though — read "What trusting this CA means" on https://get.telimatic.com/ before
# you run this.
#
# WHERE THE CERTIFICATE COMES FROM. This script does NOT embed the certificate.
# It downloads it fresh, every run, from
# https://get.telimatic.com/ca/telimatic-internal-root-ca.crt — the same origin
# that served this script — and REFUSES to trust it unless its SHA-256
# fingerprint equals the value pinned below. See "What the fingerprint pin does
# and does not do" further down: the pin catches a truncated download or a
# certificate swapped in a change nobody reviewed; it is not a substitute for
# fetching this script over a connection you trust.
#
# IDEMPOTENT. Running it twice is a no-op the second time; it says so and exits 0.
#
# FIREFOX IS NOT COVERED. Firefox ships its own trust store and ignores the
# operating system's. Either set its `security.enterprise_roots.enabled`
# preference to true (about:config) so it reads the OS store, or import the
# certificate by hand in Settings → Privacy & Security → Certificates → View
# Certificates → Authorities → Import. Chrome, Edge and Safari use the OS store
# and need nothing extra. Chrome on LINUX is the exception and uses NSS; this
# script handles that too, when `certutil` is available.

set -euo pipefail

CERT_NAME="Telimatic Internal Root CA"
CERT_URL="https://get.telimatic.com/ca/telimatic-internal-root-ca.crt"
LINUX_ANCHOR="/usr/local/share/ca-certificates/telimatic-internal-root-ca.crt"

# ---------------------------------------------------------------------------
# THE PIN. This is the SHA-256 fingerprint the downloaded certificate must
# match, written out separately from the download on purpose: if the two ever
# disagree, this script refuses to install anything.
#
# BE HONEST ABOUT WHAT THAT BUYS. Anyone who could alter what get.telimatic.com
# serves at the certificate URL could alter this script (served from the same
# origin) too, so the pin is NOT protection against a hostile origin — the
# HTTPS connection to get.telimatic.com, and whatever review gates a change to
# that repository, is what protects you there. What the pin DOES catch is a
# truncated download, a mangled copy-and-paste if you saved this file by hand,
# and a certificate quietly swapped in a change nobody read. It also gives you
# something to compare out of band: ask a colleague to read you the fingerprint
# this script printed, or check it against
# roles/internal-ca-trust/files/telimatic-internal-root-ca.crt in the Telimatic
# ansible repository, which is where this certificate is version-controlled.
# ---------------------------------------------------------------------------
EXPECTED_FP="4A107FF153744DA64C70DD19F51EE9F622190698 6FE3FBD113AE180195C26C79"
EXPECTED_FP="${EXPECTED_FP// /}"   # split only so it fits a line; compared without spaces

ACTION="install"
for arg in "$@"; do
    case "${arg}" in
        --uninstall|-u) ACTION="uninstall" ;;
        --show|-s)      ACTION="show" ;;
        --help|-h)
            # Printed inline rather than read out of $0: the normal way to run
            # this is `curl … | bash`, where $0 is "bash" and there is no file
            # to read the header comment back out of.
            cat <<'USAGE'
install.sh — trust the Telimatic internal root CA on this machine.

  install    curl -fsSL https://get.telimatic.com/ca/install.sh | bash
  remove     curl -fsSL https://get.telimatic.com/ca/install.sh | bash -s -- --uninstall
  inspect    curl -fsSL https://get.telimatic.com/ca/install.sh | bash -s -- --show

--show downloads the certificate, verifies its fingerprint, prints its subject,
expiry, SHA-256 fingerprint and name constraint, and changes nothing. Run that
first if you want to look before you leap.

The certificate is PUBLIC and is downloaded fresh from
https://get.telimatic.com/ca/telimatic-internal-root-ca.crt on every run — it is
not embedded in this script. The signing key is not in it, and is not on any
machine this script touches. The certificate is name-constrained to
telimatic.internal, so it cannot vouch for any other website.

Firefox uses its own trust store and is NOT covered — set
security.enterprise_roots.enabled to true in about:config, or import by hand.
USAGE
            exit 0
            ;;
        *)
            echo "unknown option: ${arg} (try --help)" >&2
            exit 2
            ;;
    esac
done

# ALREADY ROOT MEANS NO sudo, AND THAT IS NOT A CONVENIENCE. Many Linux boxes —
# containers and minimal server images especially — run as root and do not have
# sudo installed at all, where a hard-coded `sudo` fails with "command not found"
# AFTER the script has already printed "Installing…". Found by running this
# script in a clean ubuntu:24.04 container.
if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi

say()  { printf '%s\n' "$*"; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

command -v openssl >/dev/null 2>&1 || die "openssl is not installed, so this script cannot verify the certificate before trusting it. Install openssl and re-run."
command -v curl >/dev/null 2>&1 || die "curl is not installed, so this script cannot download the certificate. Install curl and re-run."

# --------------------------------------------------------------------------
# DOWNLOAD the certificate and CHECK IT BEFORE ANYTHING TRUSTS IT. Nothing
# below this point trusts CERT_FILE until the fingerprint compares equal.
# --------------------------------------------------------------------------
TMPDIR_SELF="$(mktemp -d)"
trap 'rm -rf "${TMPDIR_SELF}"' EXIT
CERT_FILE="${TMPDIR_SELF}/telimatic-internal-root-ca.crt"

say "Downloading the certificate from ${CERT_URL} ..."
curl -fsSL "${CERT_URL}" -o "${CERT_FILE}" \
    || die "could not download the certificate from ${CERT_URL}. Check your network connection and try again."

openssl x509 -in "${CERT_FILE}" -noout >/dev/null 2>&1 \
    || die "what was downloaded from ${CERT_URL} is not a readable certificate. It may have been truncated, or the origin may be serving something unexpected. Do not proceed — try again, and if it still fails, tell whoever gave you the link."

ACTUAL_FP="$(openssl x509 -in "${CERT_FILE}" -noout -fingerprint -sha256 \
    | cut -d= -f2 | tr -d ':' | tr '[:lower:]' '[:upper:]')"

if [ "${ACTUAL_FP}" != "${EXPECTED_FP}" ]; then
    die "FINGERPRINT MISMATCH — refusing to trust anything.
  this script pins        : ${EXPECTED_FP}
  the downloaded certificate: ${ACTUAL_FP}
The certificate served at ${CERT_URL} does not match what this script expects.
Do not run further. Try again in case of a transient/corrupted download; if it
still mismatches, tell whoever gave you the link before doing anything else."
fi

SUBJECT="$(openssl x509 -in "${CERT_FILE}" -noout -subject | cut -d= -f2-)"  # drops the leading "subject="
NOT_AFTER="$(openssl x509 -in "${CERT_FILE}" -noout -enddate | cut -d= -f2-)"
CONSTRAINTS="$(openssl x509 -in "${CERT_FILE}" -noout -text | awk '/X509v3 Name Constraints/{f=1;next} f&&/DNS:/{print $0; exit}' | tr -d ' ')"

say "Telimatic internal root CA"
say "  subject      : ${SUBJECT}"
say "  expires      : ${NOT_AFTER}"
say "  SHA-256      : ${ACTUAL_FP}"
say "  limited to   : ${CONSTRAINTS:-NONE — see the warning below}"
if [ -z "${CONSTRAINTS}" ]; then
    say ""
    say "  WARNING: this certificate declares NO name constraint, which means trusting it"
    say "  would let it vouch for ANY website. That is not what this CA is supposed to be."
    say "  Stop and ask before continuing."
    exit 1
fi
say ""

if [ "${ACTION}" = "show" ]; then
    exit 0
fi

OS="$(uname -s)"

# ==========================================================================
# macOS
# ==========================================================================
macos_hash_present() {
    /usr/bin/security find-certificate -a -Z -c "${CERT_NAME}" \
        /Library/Keychains/System.keychain 2>/dev/null \
        | grep -qi "SHA-256 hash: ${ACTUAL_FP}"
}

macos_install() {
    if macos_hash_present; then
        say "Already installed in the System keychain — nothing to do."
        say "(If Chrome still warns, quit and reopen it: it caches trust decisions.)"
        return 0
    fi
    say "Adding to the System keychain. macOS will ask for your password unless you are already root."
    ${SUDO} /usr/bin/security add-trusted-cert -d -r trustRoot \
        -k /Library/Keychains/System.keychain "${CERT_FILE}"
    # Read the write back: add-trusted-cert can succeed and be undone by a
    # profile or MDM policy, and a return code alone would not show that.
    if macos_hash_present; then
        say "Installed. Quit and reopen Chrome for it to take effect."
    else
        die "the certificate does not appear in the System keychain after adding it. If this Mac is managed, an MDM configuration profile may be controlling the trust store — ask IT."
    fi
}

macos_uninstall() {
    if ! macos_hash_present; then
        say "Not present in the System keychain — nothing to remove."
        return 0
    fi
    say "Removing from the System keychain. macOS will ask for your password unless you are already root."
    ${SUDO} /usr/bin/security delete-certificate -Z "${ACTUAL_FP}" \
        /Library/Keychains/System.keychain
    if macos_hash_present; then
        die "the certificate is still in the System keychain after removing it."
    fi
    say "Removed. Quit and reopen Chrome."
}

# ==========================================================================
# Linux — the OS anchor store, plus the NSS database Chrome actually reads.
# ==========================================================================
linux_refresh() {
    if command -v update-ca-certificates >/dev/null 2>&1; then
        ${SUDO} update-ca-certificates >/dev/null
    elif command -v update-ca-trust >/dev/null 2>&1; then
        ${SUDO} update-ca-trust extract
    else
        die "neither update-ca-certificates (Debian/Ubuntu) nor update-ca-trust (RHEL/Fedora) is present, so this script cannot refresh the system trust store on this distribution. Install the certificate by hand."
    fi
}

linux_nss() {
    # Chrome and Chromium on Linux read ~/.pki/nssdb, NOT the system store.
    # Handled only when certutil is present — it ships in libnss3-tools, and
    # installing packages is not this script's business.
    command -v certutil >/dev/null 2>&1 || {
        say "NOTE: certutil is not installed, so Chrome's own trust store was not updated."
        say "      Chrome and Chromium on Linux read ~/.pki/nssdb rather than the system store."
        say "      Install libnss3-tools (or nss-tools) and re-run this script to cover them."
        return 0
    }
    mkdir -p "${HOME}/.pki/nssdb"
    [ -f "${HOME}/.pki/nssdb/cert9.db" ] || certutil -d "sql:${HOME}/.pki/nssdb" -N --empty-password >/dev/null 2>&1 || true
    if [ "$1" = "install" ]; then
        certutil -d "sql:${HOME}/.pki/nssdb" -D -n "${CERT_NAME}" >/dev/null 2>&1 || true
        certutil -d "sql:${HOME}/.pki/nssdb" -A -t "C,," -n "${CERT_NAME}" -i "${CERT_FILE}"
        say "Added to Chrome's own trust store (~/.pki/nssdb)."
    else
        certutil -d "sql:${HOME}/.pki/nssdb" -D -n "${CERT_NAME}" >/dev/null 2>&1 || true
        say "Removed from Chrome's own trust store (~/.pki/nssdb)."
    fi
}

linux_install() {
    if [ -f "${LINUX_ANCHOR}" ] \
       && [ "$(openssl x509 -in "${LINUX_ANCHOR}" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ':' | tr '[:lower:]' '[:upper:]')" = "${ACTUAL_FP}" ]; then
        say "Already installed at ${LINUX_ANCHOR} — nothing to do for the system store."
    else
        say "Installing to ${LINUX_ANCHOR}. Your password may be requested."
        ${SUDO} install -m 0644 "${CERT_FILE}" "${LINUX_ANCHOR}"
        linux_refresh
        say "Installed into the system trust store."
    fi
    linux_nss install
}

linux_uninstall() {
    if [ -f "${LINUX_ANCHOR}" ]; then
        say "Removing ${LINUX_ANCHOR}. Your password may be requested."
        ${SUDO} rm -f "${LINUX_ANCHOR}"
        linux_refresh
        say "Removed from the system trust store."
    else
        say "Not present at ${LINUX_ANCHOR} — nothing to remove from the system store."
    fi
    linux_nss uninstall
}

# NOT `[ cond ] && install || uninstall`: under `set -e` that idiom runs the
# UNINSTALL branch whenever the install branch returns non-zero, which is the
# opposite of what a failed install should do.
case "${OS}" in
    Darwin)
        if [ "${ACTION}" = "install" ]; then macos_install; else macos_uninstall; fi
        ;;
    Linux)
        if [ "${ACTION}" = "install" ]; then linux_install; else linux_uninstall; fi
        ;;
    *)
        die "unsupported operating system: ${OS}. On Windows use install.ps1 instead."
        ;;
esac

say ""
say "Firefox keeps its own trust store and ignores the operating system's."
say "Set security.enterprise_roots.enabled to true in about:config, or import the"
say "certificate under Settings -> Privacy & Security -> Certificates -> Authorities."
