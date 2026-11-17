#!/usr/bin/env bash
# telimatic-setup.sh: set up a teammate's Mac (or Linux machine) for Telimatic in one command.
#
#   everything:   curl -fsSL https://get.telimatic.com/setup/telimatic-setup.sh | bash
#   just look:    curl -fsSL https://get.telimatic.com/setup/telimatic-setup.sh | bash -s -- --show
#   remove:       curl -fsSL https://get.telimatic.com/setup/telimatic-setup.sh | bash -s -- --uninstall
#
# It does four things, in this order, and prints them all before it changes anything:
#   1. CA TRUST. The Telimatic internal root CA goes into the System keychain (Linux: the system
#      anchors, plus Chrome's own NSS store), so *.telimatic.internal sites open without a warning.
#      This is the only part that needs sudo.
#   2. STEP. The smallstep CLI (`step`). A `step` already on PATH (for example from Homebrew) is
#      used as it is. Otherwise the script downloads ONE pinned release from
#      github.com/smallstep/cli, checks it against the SHA-256 written below, and installs it to
#      ~/.local/bin/step, with no Homebrew and no sudo. It adds ~/.local/bin to PATH in your shell's
#      login file (~/.zprofile for zsh), so new terminals find it.
#   3. STEP SETTINGS. step's own defaults (`$(step path)/config/defaults.json`): the CA URL
#      https://ssh-ca.telimatic.internal and this certificate as its root, so `step ssh login`
#      needs no --ca-url or --root. `step ca bootstrap` cannot do it: it saves step-ca's OWN root,
#      but that name is served by nginx with a certificate of THIS CA (ADR-0038
#      ca-on-runner-host), so every later step command would refuse the connection.
#   4. SIGN-IN. It asks for your Telimatic Google email and your username (the `username` of your
#      row in the ansible `users` list; it is NOT always the part of your email before the @), and
#      runs `step ssh login`. A browser opens for the Google sign-in. A username that starts with
#      `ext-` (an outside person) signs in through the `google-outside` provisioner; any other
#      through `google` (docs/runbooks/ssh-certificates.md, "Get step on your laptop (staff, Mac or Windows)").
#
# Options: --show (print the plan, change nothing), --ca-only (part 1 only), --step (parts 2-4,
# no sudo), --uninstall, --no-login, --email <you@telimatic.com>, --user <username>, --yes (no
# "press Enter" pause). Run it again at any time: a part that is already done says so and
# changes nothing.
#
# WHAT YOU ARE TRUSTING, IN ONE PARAGRAPH. The certificate below is PUBLIC: the CA's public half.
# The private key that signs with it lives only in Oracle Cloud vaults and is not in this script,
# this repository, or on any server. The certificate carries a CRITICAL X.509 name constraint
# permitting DNS:telimatic.internal and nothing else, which means a correct TLS client REJECTS
# anything this CA signs for any other name: it cannot vouch for google.com, your bank, or your
# employer's real domain. That constraint is what makes installing it on a personal machine
# reasonable. Read "What this does and does not give away" in the README beside this script.
#
# FIREFOX IS NOT COVERED. Firefox ships its own trust store and ignores the operating system's.
# Set its `security.enterprise_roots.enabled` preference to true (about:config), or import the
# certificate by hand under Settings -> Privacy & Security -> Certificates -> Authorities.
#
# THE WHOLE SCRIPT IS ONE BRACE GROUP, from the `{` below to the `}` on its last line. With
# `curl | bash`, bash runs a script while it is still downloading, one command at a time; it runs a
# brace group only once it has read the whole group. So a download cut short runs nothing at all
# (a cut just after `main` would otherwise run `main` with no options: an install in place of a
# --show). And every command that could read standard input gets /dev/tty or /dev/null, because
# standard input IS the rest of this script.
{
set -euo pipefail

CERT_NAME="Telimatic Internal Root CA"
LINUX_ANCHOR="/usr/local/share/ca-certificates/telimatic-internal-root-ca.crt"
STEP_CA_URL="https://ssh-ca.telimatic.internal"

# ---------------------------------------------------------------------------
# THE PIN. This is the SHA-256 fingerprint of the certificate embedded below,
# written out separately on purpose: if the two ever disagree, this script
# refuses to install anything.
#
# BE HONEST ABOUT WHAT THAT BUYS. Anyone who could swap the certificate in this
# file could swap this line too, so the pin is NOT protection against a hostile
# copy of the script: the HTTPS origin you fetched it from is what protects you
# there. What it does catch is a truncated download, a mangled copy-and-paste,
# and a certificate quietly replaced in a diff nobody read. It also gives you
# something to compare out of band: ask a colleague to read you the fingerprint
# the script printed, or check it against
# roles/internal-ca-trust/files/telimatic-internal-root-ca.crt in the Telimatic
# ansible repository, which is where this certificate is version-controlled.
# ---------------------------------------------------------------------------
EXPECTED_FP="4A107FF153744DA64C70DD19F51EE9F622190698 6FE3FBD113AE180195C26C79"
EXPECTED_FP="${EXPECTED_FP// /}"   # split only so it fits a line; compared without spaces

read -r -d '' CERT_PEM <<'PEM' || true
-----BEGIN CERTIFICATE-----
MIICHDCCAaGgAwIBAgIUe5COTVkn4ecwL5uE2jQbdnfJNYgwCgYIKoZIzj0EAwIw
OTESMBAGA1UECgwJVGVsaW1hdGljMSMwIQYDVQQDDBpUZWxpbWF0aWMgSW50ZXJu
YWwgUm9vdCBDQTAgFw0yNjA3MTAxNjU0NTNaGA8yMTI2MDcxMDE2NTQ1M1owOTES
MBAGA1UECgwJVGVsaW1hdGljMSMwIQYDVQQDDBpUZWxpbWF0aWMgSW50ZXJuYWwg
Um9vdCBDQTB2MBAGByqGSM49AgEGBSuBBAAiA2IABOEbM3/YrbaLxsDzdgecH8Sp
1LFWN3noU1Urg2mkLKZ1hd+GKRYDsAzWBPJofn7XBdRHQtidMlXbfMiHyuSXN1Et
lqxhlWU5x7IV8qXfUWWy6qy6PFKe7i8SPlIyh0YkMqNoMGYwDwYDVR0TAQH/BAUw
AwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFF00HPA9U489H9npsNug2byZ
sHWyMCQGA1UdHgEB/wQaMBigFjAUghJ0ZWxpbWF0aWMuaW50ZXJuYWwwCgYIKoZI
zj0EAwIDaQAwZgIxAINH/nDjdu3H4kgi0CTQ95Ab2he2N7lWHYNlT0psY9e7v7MD
FIqNGw0QBWZeMcGrSwIxAIcKvXqEwf/BgZt+ecwvrKd2XNGt4rTDPJgRSVTwrf/6
eEy3+n7pKVPbPM2VXNWR3A==
-----END CERTIFICATE-----
PEM

# ---------------------------------------------------------------------------
# THE STEP RELEASE. One version, and the SHA-256 of each archive this script may
# install, copied from that release's checksums.txt
# (https://github.com/smallstep/cli/releases/download/v0.31.0/checksums.txt, sha256
# 10220d8de700735ac6afcd0f3d914be74a9711c1e43de3c094b4a6c91059ef38). That file's
# sigstore signature was checked against the certificate GitHub's OIDC issued to
# smallstep/cli's release workflow for the tag v0.31.0, and each value equals the
# digest GitHub's release API reports for the asset (2026-11-17). A download whose
# SHA-256 differs is refused: nothing is installed.
#
# TO MOVE TO A NEW VERSION: change STEP_VERSION and the four values here, and
# $StepVersion and its two values in telimatic-setup.ps1, from the new release's
# checksums.txt, in one commit (tests/team-setup-rig checks both files name the
# same version).
# ---------------------------------------------------------------------------
STEP_VERSION="0.31.0"
STEP_SHA256_DARWIN_ARM64="91963c7c1ef6654dda61ff2f99cff2b8e95efce198d8c7b3532a00a8f253bf41"
STEP_SHA256_DARWIN_AMD64="4b928a936e9d2ff3bfa6f7638003a9e46c702a27cf515169c6e5996ade8cd23e"
STEP_SHA256_LINUX_ARM64="9937964c7d47de47a511cd775bd07101b8ee9854db210abd402c69093f0a6fd4"
STEP_SHA256_LINUX_AMD64="a7e13726efa8782f3d5459174dacf602ab3514b9431f2d42a6a75950b7685e5f"
STEP_RELEASE_URL="https://github.com/smallstep/cli/releases/download/v${STEP_VERSION}"

# The marker on the one line this script adds to a shell login file. The line is
# found again by this marker, so a second run adds nothing.
PATH_MARK="# added by telimatic-setup: the step CLI"

usage() {
    # Printed inline rather than read out of $0: with `curl | bash`, $0 is "bash".
    cat <<'USAGE'
telimatic-setup.sh: trust the Telimatic internal CA, install and set up the step CLI,
and sign in for an SSH certificate. Every part that is already done is left as it is.

  everything   curl -fsSL https://get.telimatic.com/setup/telimatic-setup.sh | bash
  look only    curl -fsSL https://get.telimatic.com/setup/telimatic-setup.sh | bash -s -- --show
  CA only      curl -fsSL https://get.telimatic.com/setup/telimatic-setup.sh | bash -s -- --ca-only
  step only    curl -fsSL https://get.telimatic.com/setup/telimatic-setup.sh | bash -s -- --step       (no sudo)
  remove       curl -fsSL https://get.telimatic.com/setup/telimatic-setup.sh | bash -s -- --uninstall

  --email <you@telimatic.com>  your Telimatic Google sign-in (else the script asks)
  --user <username>            your username on our hosts (else the script asks)
  --no-login                   do not sign in at the end
  --yes                        do not pause before the changes

--show prints the certificate, then each change the script would make, and changes nothing.

The certificate in this script is PUBLIC. The signing key is not in it, and is not on any
machine this script touches. The certificate is name-constrained to telimatic.internal, so it
cannot vouch for any other website.

Firefox uses its own trust store and is NOT covered: set security.enterprise_roots.enabled to
true in about:config, or import the certificate by hand.
USAGE
}

say()  { printf '%s\n' "$*"; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# A terminal to ask questions on. With `curl | bash` standard input is the script, so every
# question is read from /dev/tty, and there is no question at all without one.
have_tty() { { : </dev/tty; } 2>/dev/null; }

ask() {
    local answer=""
    printf '%s' "$1" >/dev/tty
    IFS= read -r answer </dev/tty || answer=""
    printf '%s' "${answer}"
}

parse_args() {
    ACTION="install"
    NO_LOGIN=0
    ASSUME_YES=0
    EMAIL=""
    LOGIN_USER=""
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --uninstall|-u) ACTION="uninstall" ;;
            --show|-s)      ACTION="show" ;;
            --ca-only)      ACTION="ca-only" ;;
            --step)         ACTION="step" ;;
            --no-login)     NO_LOGIN=1 ;;
            --yes|-y)       ASSUME_YES=1 ;;
            --email)        [ "$#" -ge 2 ] || die "--email needs a value"; EMAIL="$2"; shift ;;
            --email=*)      EMAIL="${1#--email=}" ;;
            --user)         [ "$#" -ge 2 ] || die "--user needs a value"; LOGIN_USER="$2"; shift ;;
            --user=*)       LOGIN_USER="${1#--user=}" ;;
            --help|-h)      usage; exit 0 ;;
            *)              die "unknown option: $1 (try --help)" ;;
        esac
        shift
    done
}

# ==========================================================================
# The certificate: write it out and CHECK IT BEFORE ANYTHING TRUSTS IT.
# ==========================================================================
check_cert() {
    CERT_FILE="${TMPDIR_SELF}/telimatic-internal-root-ca.crt"
    printf '%s\n' "${CERT_PEM}" > "${CERT_FILE}"

    openssl x509 -in "${CERT_FILE}" -noout >/dev/null 2>&1 \
        || die "the certificate embedded in this script is not a readable certificate: your copy is damaged. Download it again."

    ACTUAL_FP="$(openssl x509 -in "${CERT_FILE}" -noout -fingerprint -sha256 \
        | cut -d= -f2 | tr -d ':' | tr '[:lower:]' '[:upper:]')"

    if [ "${ACTUAL_FP}" != "${EXPECTED_FP}" ]; then
        die "FINGERPRINT MISMATCH: refusing to trust anything.
  this script pins : ${EXPECTED_FP}
  the certificate  : ${ACTUAL_FP}
Your copy of this script has been altered or truncated. Do not run it. Fetch it again
from the original link, and if it still mismatches, tell whoever gave you the link."
    fi

    local subject not_after constraints
    subject="$(openssl x509 -in "${CERT_FILE}" -noout -subject | cut -d= -f2-)"  # drops "subject="
    not_after="$(openssl x509 -in "${CERT_FILE}" -noout -enddate | cut -d= -f2-)"
    constraints="$(openssl x509 -in "${CERT_FILE}" -noout -text | awk '/X509v3 Name Constraints/{f=1;next} f&&/DNS:/{print $0; exit}' | tr -d ' ')"

    say "Telimatic internal root CA"
    say "  subject      : ${subject}"
    say "  expires      : ${not_after}"
    say "  SHA-256      : ${ACTUAL_FP}"
    say "  limited to   : ${constraints:-NONE (see the warning below)}"
    if [ -z "${constraints}" ]; then
        say ""
        say "  WARNING: this certificate declares NO name constraint, which means trusting it"
        say "  would let it vouch for ANY website. That is not what this CA is supposed to be."
        say "  Stop and ask before continuing."
        exit 1
    fi
    say ""
}

# ==========================================================================
# Part 1: CA trust. macOS: the System keychain. Linux: the OS anchor store,
# plus the NSS database Chrome actually reads.
# ==========================================================================
macos_hash_present() {
    local found=""
    found="$(/usr/bin/security find-certificate -a -Z -c "${CERT_NAME}" \
        /Library/Keychains/System.keychain 2>/dev/null </dev/null)" || true
    printf '%s\n' "${found}" | grep -qi "SHA-256 hash: ${ACTUAL_FP}"
}

# TRUSTED, not only present. `security add-trusted-cert` adds the certificate to the keychain
# FIRST and saves its trust setting SECOND (Apple Security, SecurityTool/macOS/trusted_cert_add.c:
# SecCertificateAddToKeychain, then SecTrustSettingsSetTrustSettings). When the second step fails
# (the person cancels the "System Certificate Trust Settings" dialog, or there is no desktop
# session, as over SSH), the certificate stays in the keychain with no trust. So "done" is a trust
# evaluation of the certificate itself: `verify-cert` exits 0 only for a trust result of Proceed or
# Unspecified (SecurityTool/macOS/verify_cert.c); -l because the certificate is a CA, -L for no
# network fetch, -q for no output. (Read from Apple's source; not yet run on a Mac.)
macos_trusted() {
    /usr/bin/security verify-cert -c "${CERT_FILE}" -l -L -q >/dev/null 2>&1 </dev/null
}

linux_anchor_present() {
    [ -f "${LINUX_ANCHOR}" ] \
        && [ "$(openssl x509 -in "${LINUX_ANCHOR}" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ':' | tr '[:lower:]' '[:upper:]')" = "${ACTUAL_FP}" ]
}

ca_present() {
    case "${OS}" in
        Darwin) macos_hash_present && macos_trusted ;;
        Linux)  linux_anchor_present ;;
    esac
}

ca_supported() {
    case "${OS}" in
        Darwin|Linux) return 0 ;;
        *) die "unsupported operating system: ${OS}. On Windows use telimatic-setup.ps1 instead." ;;
    esac
}

macos_install() {
    if macos_hash_present && macos_trusted; then
        say "CA trust: already trusted in the System keychain, nothing to do."
        say "(If Chrome still warns, quit and reopen it: it caches trust decisions.)"
        return 0
    fi
    local was_there=0 rc=0
    if macos_hash_present; then was_there=1; fi
    say "CA trust: adding to the System keychain. macOS asks for your password unless you are root,"
    say "          then shows a dialog to change the trust settings: approve it."
    ${SUDO} /usr/bin/security add-trusted-cert -d -r trustRoot \
        -k /Library/Keychains/System.keychain "${CERT_FILE}" </dev/null || rc=$?
    # Read the write back as a TRUST evaluation, not presence: see macos_trusted. A profile or MDM
    # policy can also undo the write, and a return code alone would not show either.
    if macos_hash_present && macos_trusted; then
        say "CA trust: installed and trusted. Quit and reopen Chrome for it to take effect."
        return 0
    fi
    # Half done: in the keychain, not trusted. Take out what this run added, so that no later run
    # (or person) reads the certificate's presence as trust.
    if [ "${was_there}" = 0 ] && macos_hash_present; then
        ${SUDO} /usr/bin/security delete-certificate -Z "${ACTUAL_FP}" \
            /Library/Keychains/System.keychain </dev/null >/dev/null 2>&1 || true
    fi
    die "the certificate is NOT trusted (security add-trusted-cert exit ${rc}). The usual cause: the macOS
dialog for the trust settings was cancelled, or this Terminal is not on the Mac's own desktop (an SSH
session cannot show it). Run the script again in Terminal on the Mac and approve the dialog. If this
Mac is managed, an MDM configuration profile may control the trust store: ask IT."
}

macos_uninstall() {
    if ! macos_hash_present; then
        say "CA trust: not in the System keychain, nothing to remove."
        return 0
    fi
    say "CA trust: removing from the System keychain. macOS asks for your password unless you are root."
    # -t: remove the certificate's trust settings too (without it they stay behind: Apple
    # SecurityTool/macOS/keychain_delete.c removes trust settings only with -t).
    ${SUDO} /usr/bin/security delete-certificate -t -Z "${ACTUAL_FP}" \
        /Library/Keychains/System.keychain </dev/null
    if macos_hash_present; then
        die "the certificate is still in the System keychain after removing it."
    fi
    say "CA trust: removed. Quit and reopen Chrome."
}

linux_refresh() {
    if command -v update-ca-certificates >/dev/null 2>&1; then
        ${SUDO} update-ca-certificates >/dev/null </dev/null
    elif command -v update-ca-trust >/dev/null 2>&1; then
        ${SUDO} update-ca-trust extract </dev/null
    else
        die "neither update-ca-certificates (Debian/Ubuntu) nor update-ca-trust (RHEL/Fedora) is present, so this script cannot refresh the system trust store on this distribution. Install the certificate by hand."
    fi
}

linux_nss() {
    # Chrome and Chromium on Linux read ~/.pki/nssdb, NOT the system store.
    # Handled only when certutil is present: it ships in libnss3-tools, and
    # installing packages is not this script's business.
    command -v certutil >/dev/null 2>&1 || {
        say "NOTE: certutil is not installed, so Chrome's own trust store was not updated."
        say "      Chrome and Chromium on Linux read ~/.pki/nssdb rather than the system store."
        say "      Install libnss3-tools (or nss-tools) and re-run this script to cover them."
        return 0
    }
    mkdir -p "${HOME}/.pki/nssdb"
    [ -f "${HOME}/.pki/nssdb/cert9.db" ] || certutil -d "sql:${HOME}/.pki/nssdb" -N --empty-password >/dev/null 2>&1 </dev/null || true
    if [ "$1" = "install" ]; then
        certutil -d "sql:${HOME}/.pki/nssdb" -D -n "${CERT_NAME}" >/dev/null 2>&1 </dev/null || true
        certutil -d "sql:${HOME}/.pki/nssdb" -A -t "C,," -n "${CERT_NAME}" -i "${CERT_FILE}" </dev/null
        say "CA trust: added to Chrome's own trust store (~/.pki/nssdb)."
    else
        certutil -d "sql:${HOME}/.pki/nssdb" -D -n "${CERT_NAME}" >/dev/null 2>&1 </dev/null || true
        say "CA trust: removed from Chrome's own trust store (~/.pki/nssdb)."
    fi
}

linux_install() {
    if linux_anchor_present; then
        say "CA trust: already at ${LINUX_ANCHOR}, nothing to do for the system store."
    else
        say "CA trust: installing to ${LINUX_ANCHOR}. Your password may be requested."
        ${SUDO} install -m 0644 "${CERT_FILE}" "${LINUX_ANCHOR}" </dev/null
        linux_refresh
        say "CA trust: installed into the system trust store."
    fi
    linux_nss install
}

linux_uninstall() {
    if [ -f "${LINUX_ANCHOR}" ]; then
        say "CA trust: removing ${LINUX_ANCHOR}. Your password may be requested."
        ${SUDO} rm -f "${LINUX_ANCHOR}" </dev/null
        linux_refresh
        say "CA trust: removed from the system trust store."
    else
        say "CA trust: not at ${LINUX_ANCHOR}, nothing to remove from the system store."
    fi
    linux_nss uninstall
}

# NOT `[ cond ] && install || uninstall`: under `set -e` that idiom runs the
# UNINSTALL branch whenever the install branch returns non-zero, which is the
# opposite of what a failed install should do.
ca_install() {
    case "${OS}" in
        Darwin) macos_install ;;
        Linux)  linux_install ;;
    esac
    # Drop sudo's cached password: the downloaded step and the sign-in run next, in this terminal.
    if [ -n "${SUDO}" ]; then sudo -k </dev/null || true; fi
}

ca_uninstall() {
    case "${OS}" in
        Darwin) macos_uninstall ;;
        Linux)  linux_uninstall ;;
    esac
}

# ==========================================================================
# Part 2: the step CLI. Never under sudo: under sudo, HOME is still the
# person's on macOS, so every file would be made root-owned in their home,
# and later step commands run as them would fail on them.
# ==========================================================================
step_as_sudo() {
    [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]
}

# The first line of `step version`, read whole before it is looked at: a `| grep -q` that
# stops reading early can kill the writer with SIGPIPE, and under pipefail that reads as a
# failure.
step_version_line() {
    local v=""
    v="$("$1" version 2>/dev/null </dev/null)" || true
    printf '%s\n' "${v%%$'\n'*}"
}

is_smallstep() {
    case "$(step_version_line "$1")" in
        "Smallstep CLI/"*) return 0 ;;
    esac
    return 1
}

# STEP = the step to use, or empty. A `step` on PATH first (Homebrew's, or ours
# from an earlier run); then ours in STEP_BIN_DIR when PATH does not have it yet.
# OUR copy (STEP_BIN_DIR/step, from an earlier run) is used only when it is the pinned version:
# when the pin moves (a security fix), the next run installs the new one; a copy that does not
# run at all is replaced too. Any other step on PATH (Homebrew's) is the person's, used as it is.
find_step() {
    STEP=""
    local on_path=""
    on_path="$(command -v step 2>/dev/null)" || on_path=""
    if [ -n "${on_path}" ] && [ "${on_path}" != "${STEP_BIN_DIR}/step" ]; then
        is_smallstep "${on_path}" \
            || die "the program named step at ${on_path} is not the smallstep CLI (\`step version\` does not say \"Smallstep CLI\"). Remove or rename it, then run this script again."
        STEP="${on_path}"
    elif [ -x "${STEP_BIN_DIR}/step" ] && is_pinned_step "${STEP_BIN_DIR}/step"; then
        STEP="${STEP_BIN_DIR}/step"
    fi
}

is_pinned_step() {
    case "$(step_version_line "$1")" in
        "Smallstep CLI/${STEP_VERSION} "*) return 0 ;;
    esac
    return 1
}

# Prints "<archive name> <sha256>" for this machine, or fails.
step_asset() {
    local os arch
    case "${OS}" in
        Darwin) os="darwin" ;;
        Linux)  os="linux" ;;
        *) return 1 ;;
    esac
    arch="$(uname -m)"
    # A Terminal under Rosetta says x86_64 on an Apple Silicon Mac; the arm64 build is the right one.
    if [ "${OS}" = "Darwin" ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || true)" = "1" ]; then
        arch="arm64"
    fi
    case "${os}/${arch}" in
        darwin/arm64)          printf '%s %s\n' "step_darwin_${STEP_VERSION}_arm64.tar.gz" "${STEP_SHA256_DARWIN_ARM64}" ;;
        darwin/x86_64)         printf '%s %s\n' "step_darwin_${STEP_VERSION}_amd64.tar.gz" "${STEP_SHA256_DARWIN_AMD64}" ;;
        linux/aarch64|linux/arm64) printf '%s %s\n' "step_linux_${STEP_VERSION}_arm64.tar.gz" "${STEP_SHA256_LINUX_ARM64}" ;;
        linux/x86_64)          printf '%s %s\n' "step_linux_${STEP_VERSION}_amd64.tar.gz" "${STEP_SHA256_LINUX_AMD64}" ;;
        *) return 1 ;;
    esac
}

sha256_of() {
    openssl dgst -sha256 "$1" | awk '{print $NF}' | tr '[:upper:]' '[:lower:]'
}

step_install() {
    local asset_line asset sum file got
    asset_line="$(step_asset)" \
        || die "there is no pinned step build for $(uname -s) $(uname -m). Install step yourself (https://smallstep.com/docs/step-cli/installation), then run this script again with --step."
    asset="${asset_line%% *}"
    sum="${asset_line##* }"
    file="${TMPDIR_SELF}/${asset}"
    command -v curl >/dev/null 2>&1 || die "curl is not installed, so step cannot be downloaded."
    say "step: downloading ${asset} from ${STEP_RELEASE_URL}/"
    curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 -o "${file}" "${STEP_RELEASE_URL}/${asset}" </dev/null \
        || die "the download of ${STEP_RELEASE_URL}/${asset} failed. Nothing was installed."
    got="$(sha256_of "${file}")"
    if [ "${got}" != "${sum}" ]; then
        die "SHA-256 MISMATCH for ${asset}: refusing to install it.
  this script pins : ${sum}
  the download     : ${got}
Nothing was installed. Run the script again later; if it still mismatches, tell whoever gave you the link."
    fi
    say "step: SHA-256 matches the pin (${sum})."
    tar -xzf "${file}" -C "${TMPDIR_SELF}" "step_${STEP_VERSION}/bin/step" </dev/null \
        || die "could not unpack step from ${asset}. Nothing was installed."
    # The unpacked file must run, and be the pinned version, BEFORE it goes in place: a file that
    # does not run must not be left on PATH.
    local unpacked="${TMPDIR_SELF}/step_${STEP_VERSION}/bin/step" version
    version="$(step_version_line "${unpacked}")"
    case "${version}" in
        "Smallstep CLI/${STEP_VERSION} "*) ;;
        *) die "the unpacked step answered \`step version\` with \"${version}\", not Smallstep CLI/${STEP_VERSION}. Nothing was installed." ;;
    esac
    mkdir -p "${STEP_BIN_DIR}"
    install -m 0755 "${unpacked}" "${STEP_BIN_DIR}/step"
    STEP="${STEP_BIN_DIR}/step"
    # Read it back: the installed file is the pinned version.
    is_pinned_step "${STEP}" || die "${STEP} does not answer Smallstep CLI/${STEP_VERSION} after the install."
    say "step: installed ${STEP} (${version})."
}

# The login file of the person's shell that PATH goes in, or empty when the
# shell is not one this script knows.
path_rc_file() {
    case "$(basename "${SHELL:-}")" in
        zsh)  printf '%s\n' "${ZDOTDIR:-${HOME}}/.zprofile" ;;
        bash)
            # bash reads only the FIRST of these that exists: a new ~/.bash_profile would stop
            # an existing ~/.profile from being read at all.
            local f
            for f in "${HOME}/.bash_profile" "${HOME}/.bash_login" "${HOME}/.profile"; do
                if [ -f "${f}" ]; then printf '%s\n' "${f}"; return 0; fi
            done
            if [ "${OS}" = "Darwin" ]; then printf '%s\n' "${HOME}/.bash_profile"; else printf '%s\n' "${HOME}/.profile"; fi
            ;;
        *) printf '\n' ;;
    esac
}

on_path() {
    case ":${PATH}:" in *":${STEP_BIN_DIR}:"*) return 0 ;; esac
    return 1
}

# shellcheck disable=SC2016  # the line is written with a literal $HOME and $PATH on purpose
PATH_LINE='export PATH="$HOME/.local/bin:$PATH"'

path_fix() {
    on_path && return 0
    local rc
    rc="$(path_rc_file)"
    if [ -z "${rc}" ]; then
        say "NOTE: your shell (${SHELL:-unknown}) is not zsh or bash, so PATH was not changed."
        say "      Add ${STEP_BIN_DIR} to PATH in your shell's settings."
    elif [ -f "${rc}" ] && grep -qF "${PATH_MARK}" "${rc}"; then
        :   # an earlier run added it; this terminal started before that, or did not read it
    else
        printf '\n%s  %s\n' "${PATH_LINE}" "${PATH_MARK}" >> "${rc}"
        say "step: added ${STEP_BIN_DIR} to PATH in ${rc} (new terminals)."
    fi
    say "      For THIS terminal, run:  export PATH=\"${STEP_BIN_DIR}:\$PATH\""
}

# ==========================================================================
# Part 3: step's settings: its default CA URL and root, in the person's own
# step directory (`step path`, ~/.step unless STEPPATH says otherwise). step
# checks the TLS of the CA against the ONE root file it is given, never the
# OS store, so part 1 does not reach it.
# ==========================================================================
step_files() {
    if [ -n "${STEP}" ]; then
        STEP_DIR="$("${STEP}" path </dev/null)"
    else
        STEP_DIR="${STEPPATH:-${HOME}/.step}"   # step's own default, for a plan before it is installed
    fi
    # Only an absolute path: a program named `step` that is not the smallstep CLI
    # (or an empty answer) must not make us write under the current directory or /.
    case "${STEP_DIR}" in
        /?*) ;;
        *) die "\`step path\` did not answer an absolute directory, so this \`step\` is not the smallstep CLI; nothing written for step." ;;
    esac
    STEP_ROOT="${STEP_DIR}/certs/telimatic-internal-root-ca.crt"
    STEP_DEFAULTS="${STEP_DIR}/config/defaults.json"
}

step_ours() {
    [ -f "${STEP_DEFAULTS}" ] \
        && grep -qE "\"ca-url\"[[:space:]]*:[[:space:]]*\"${STEP_CA_URL}\"" "${STEP_DEFAULTS}"
}

step_config_done() {
    step_ours && [ -f "${STEP_ROOT}" ] && cmp -s "${CERT_FILE}" "${STEP_ROOT}"
}

step_config() {
    step_files
    if step_config_done; then
        say "step settings: already point at ${STEP_CA_URL}, nothing to do."
        return 0
    fi
    mkdir -p "${STEP_DIR}/certs" "${STEP_DIR}/config"
    # The root goes in its own file name, which no other CA's settings use.
    install -m 0644 "${CERT_FILE}" "${STEP_ROOT}"
    if [ -f "${STEP_DEFAULTS}" ] && ! step_ours; then
        say "NOTE: ${STEP_DEFAULTS} already points step at another CA; it is left as it is."
        say "      Use --ca-url ${STEP_CA_URL} --root ${STEP_ROOT} on each step command instead."
        STEP_OTHER_CA=1
        return 0
    fi
    # Our file, with keys of the person's own beside ours: keep a copy before we replace it.
    if [ -f "${STEP_DEFAULTS}" ] && [ "$(grep -oE '"[A-Za-z_-]+"[[:space:]]*:' "${STEP_DEFAULTS}" | wc -l)" -gt 2 ]; then
        cp "${STEP_DEFAULTS}" "${STEP_DEFAULTS}.bak"
        say "NOTE: ${STEP_DEFAULTS} had more settings than ours; the old file is kept as ${STEP_DEFAULTS}.bak."
    fi
    printf '{\n  "ca-url": "%s",\n  "root": "%s"\n}\n' "${STEP_CA_URL}" "${STEP_ROOT}" > "${STEP_DEFAULTS}"
    say "step settings: written to ${STEP_DEFAULTS} (CA ${STEP_CA_URL}, root ${STEP_ROOT})."
}

step_unconfig() {
    find_step
    step_files   # with no usable step, step's own default directory (STEPPATH, else ~/.step)
    if step_ours; then
        rm -f "${STEP_DEFAULTS}" "${STEP_ROOT}"
        say "step settings: removed (${STEP_CA_URL})."
    else
        say "step settings: not ours, nothing to remove."
    fi
    if [ -e "${STEP_BIN_DIR}/step" ]; then
        say "NOTE: step itself stays at ${STEP_BIN_DIR}/step. To remove it too: rm ${STEP_BIN_DIR}/step"
        say "      and delete the line ending \"${PATH_MARK}\" in your shell's login file."
    fi
}

# ==========================================================================
# Part 4: sign in. The principal rule is the CA's (services/ssh-ca/templates):
# the principal is your username from the `users` list, never derived from
# your email; an `ext-` username is an outside person and signs in through
# `google-outside`.
# ==========================================================================
login_provisioner() {
    case "${LOGIN_USER}" in
        ext-*) printf 'google-outside\n' ;;
        *)     printf 'google\n' ;;
    esac
}

login_ask() {
    [ "${NO_LOGIN}" = 1 ] && return 0
    if [ -n "${EMAIL}" ] && [ -n "${LOGIN_USER}" ]; then return 0; fi
    have_tty || return 0
    say "Sign-in: the last step gets you an SSH certificate. Press Enter on an empty line to skip it."
    if [ -z "${EMAIL}" ]; then
        EMAIL="$(ask "  Your Telimatic Google email (you@telimatic.com): ")"
    fi
    if [ -n "${EMAIL}" ] && [ -z "${LOGIN_USER}" ]; then
        say "  Your username on our hosts is the \`username\` of your row in the ansible users list."
        say "  It is not always the part of your email before the @. Ask in #engineering if unsure."
        LOGIN_USER="$(ask "  Your username: ")"
    fi
    say ""
}

trim() {
    printf '%s' "$1" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

login_check_input() {
    EMAIL="$(trim "${EMAIL}")"
    LOGIN_USER="$(trim "${LOGIN_USER}")"
    [ -z "${EMAIL}" ] && [ -z "${LOGIN_USER}" ] && return 0
    EMAIL="$(printf '%s' "${EMAIL}" | tr '[:upper:]' '[:lower:]')"
    case "${EMAIL}" in
        *[[:space:]]*|*@*@*) die "\"${EMAIL}\" is not an email address." ;;
        ?*@?*.?*) ;;
        *) die "\"${EMAIL}\" is not an email address." ;;
    esac
    case "${LOGIN_USER}" in
        "") die "an email was given but no username: add --user <username>." ;;
        *[!a-z0-9_-]*) die "\"${LOGIN_USER}\" is not a username (lower-case letters, digits, - and _ only)." ;;
    esac
}

login_command() {
    printf 'step ssh login %s --provisioner %s --principal %s' "${EMAIL}" "$(login_provisioner)" "${LOGIN_USER}"
}

login() {
    [ "${NO_LOGIN}" = 1 ] && return 0
    if [ -z "${EMAIL}" ]; then
        say "Sign-in: skipped (no email given). Later, with WARP on:"
        say "  step ssh login <you>@telimatic.com --provisioner google --principal <your username>"
        return 0
    fi
    if [ -n "${STEP_OTHER_CA:-}" ]; then
        say "Sign-in: skipped, because step's settings point at another CA. With WARP on, run:"
        say "  $(login_command) --ca-url ${STEP_CA_URL} --root ${STEP_ROOT}"
        return 0
    fi
    if ! "${STEP}" ca health >/dev/null 2>&1 </dev/null; then
        say "Sign-in: ${STEP_CA_URL} does not answer. Turn on WARP (Cloudflare One), then run:"
        say "  $(login_command)"
        LOGIN_FAILED=1
        return 0
    fi
    if [ -z "${SSH_AUTH_SOCK:-}" ]; then
        say "Sign-in: no SSH agent in this terminal (SSH_AUTH_SOCK is empty). Run eval \"\$(ssh-agent)\","
        say "  then: $(login_command)"
        LOGIN_FAILED=1
        return 0
    fi
    say "Sign-in: $(login_command)"
    say "  A browser opens for the Google sign-in."
    local rc=0
    if have_tty; then
        "${STEP}" ssh login "${EMAIL}" --provisioner "$(login_provisioner)" --principal "${LOGIN_USER}" </dev/tty || rc=$?
    else
        "${STEP}" ssh login "${EMAIL}" --provisioner "$(login_provisioner)" --principal "${LOGIN_USER}" </dev/null || rc=$?
    fi
    if [ "${rc}" -ne 0 ]; then
        say ""
        say "Sign-in FAILED (step exit ${rc}). The usual causes:"
        say "  - the CA names your real username in its error (\"signs only the one principal X\"): run again with --user X;"
        say "  - SSH_AUTH_SOCK is the 1Password agent, which cannot hold a certificate: run"
        say "    eval \"\$(ssh-agent)\" in this terminal, then: $(login_command)"
        LOGIN_FAILED=1
        return 0
    fi
    # Read it back: the agent must now hold a certificate.
    local keys=""
    keys="$(ssh-add -l </dev/null 2>/dev/null)" || true
    if printf '%s\n' "${keys}" | grep -q -- '-CERT)'; then
        say "Sign-in: done. The SSH agent holds your certificate. Log in with:"
        say "  ssh ${LOGIN_USER}@<host>.telimatic.internal"
        say "  (If ~/.ssh/config sets IdentityAgent, add -o IdentityAgent=SSH_AUTH_SOCK.)"
    else
        say "Sign-in: step finished, but \`ssh-add -l\` lists no certificate. See docs/runbooks/ssh-certificates.md."
        LOGIN_FAILED=1
    fi
}

# ==========================================================================
# The plan: what each part would change, printed by --show and before any change.
# ==========================================================================
plan() {
    say "What this script does on this machine:"
    if [ "${ACTION}" != "step" ]; then
        if ca_present; then
            say "  1. CA trust      : already trusted, no change."
        elif [ "${OS}" = "Darwin" ] && macos_hash_present; then
            say "  1. CA trust      : in the System keychain but NOT trusted: set its trust${SUDO:+ (sudo: your Mac password)}."
        elif [ "${OS}" = "Darwin" ]; then
            say "  1. CA trust      : add the certificate above to the System keychain${SUDO:+ (sudo: your Mac password)}."
        else
            say "  1. CA trust      : install it to ${LINUX_ANCHOR}${SUDO:+ (sudo)}, and Chrome's ~/.pki/nssdb if certutil exists."
        fi
    fi
    [ "${ACTION}" = "ca-only" ] && { say ""; return 0; }
    if step_as_sudo; then
        say "  2-4. step        : skipped under sudo. Run this script as yourself with --step for them."
        say ""
        return 0
    fi
    find_step
    if [ -n "${STEP}" ]; then
        say "  2. step          : use ${STEP} ($(step_version_line "${STEP}")), no download."
    else
        local asset_line
        if asset_line="$(step_asset)"; then
            say "  2. step          : download ${asset_line%% *} from github.com/smallstep/cli,"
            say "                     check its SHA-256 against ${asset_line##* },"
            say "                     install it to ${STEP_BIN_DIR}/step."
        else
            say "  2. step          : NO pinned build for $(uname -s) $(uname -m): the script stops here."
        fi
    fi
    if ! on_path && { [ -z "${STEP}" ] || [ "${STEP}" = "${STEP_BIN_DIR}/step" ]; }; then
        local rc
        rc="$(path_rc_file)"
        if [ -n "${rc}" ] && [ -f "${rc}" ] && grep -qF "${PATH_MARK}" "${rc}"; then
            say "                     PATH: ${rc} already adds ${STEP_BIN_DIR}, no change."
        elif [ -n "${rc}" ]; then
            say "                     PATH: add one line to ${rc}: ${PATH_LINE}"
        else
            say "                     PATH: your shell is not zsh or bash; add ${STEP_BIN_DIR} to PATH yourself."
        fi
    fi
    step_files
    if step_config_done; then
        say "  3. step settings : already point at ${STEP_CA_URL}, no change."
    elif [ -f "${STEP_DEFAULTS}" ] && ! step_ours; then
        say "  3. step settings : ${STEP_DEFAULTS} points at another CA: left as it is."
    else
        say "  3. step settings : write ${STEP_DEFAULTS} (ca-url ${STEP_CA_URL}) and ${STEP_ROOT}."
    fi
    if [ "${NO_LOGIN}" = 1 ]; then
        say "  4. sign-in       : skipped (--no-login)."
    elif [ -n "${EMAIL}" ]; then
        say "  4. sign-in       : $(login_command)  (a browser opens)"
    elif [ "${ACTION}" = "show" ]; then
        say "  4. sign-in       : ask your email and username, then run step ssh login (a browser opens)."
    else
        say "  4. sign-in       : skipped (no email given)."
    fi
    say ""
}

pause() {
    [ "${ASSUME_YES}" = 1 ] && return 0
    have_tty || return 0
    ask "Press Enter to go on, or Ctrl-C to stop. " >/dev/null
    say ""
}

main() {
    parse_args "$@"
    OS="$(uname -s)"
    STEP_BIN_DIR="${HOME}/.local/bin"
    STEP_OTHER_CA=""
    LOGIN_FAILED=""

    # ALREADY ROOT MEANS NO sudo, AND THAT IS NOT A CONVENIENCE. Many Linux boxes
    # (containers and minimal server images especially) run as root and do not have
    # sudo installed at all, where a hard-coded `sudo` fails with "command not found"
    # AFTER the script has already printed "Installing...". Found by running this
    # script in a clean ubuntu:24.04 container.
    if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi

    command -v openssl >/dev/null 2>&1 || die "openssl is not installed, so this script cannot verify the certificate before trusting it. Install openssl and re-run."
    ca_supported

    TMPDIR_SELF="$(mktemp -d)"
    trap 'rm -rf "${TMPDIR_SELF}"' EXIT

    check_cert

    case "${ACTION}" in
        show)
            login_check_input
            plan
            say "--show: nothing was changed."
            return 0
            ;;
        uninstall)
            ca_uninstall
            if step_as_sudo; then
                say "NOTE: run under sudo, so step's settings were not removed. Run this script again as yourself with --uninstall."
            else
                step_unconfig
            fi
            return 0
            ;;
    esac

    if [ "${ACTION}" != "ca-only" ] && ! step_as_sudo; then
        login_ask
        login_check_input
    fi
    plan
    pause

    if [ "${ACTION}" != "step" ]; then
        ca_install
    fi
    if [ "${ACTION}" != "ca-only" ]; then
        if step_as_sudo; then
            say "NOTE: run under sudo, so step was not set up. Run this script again as yourself with --step."
        else
            find_step
            if [ -n "${STEP}" ]; then
                say "step: using ${STEP} ($(step_version_line "${STEP}"))."
            else
                step_install
            fi
            if [ "${STEP}" = "${STEP_BIN_DIR}/step" ]; then path_fix; fi
            step_config
            login
        fi
    fi

    say ""
    say "Firefox keeps its own trust store and ignores the operating system's."
    say "Set security.enterprise_roots.enabled to true in about:config, or import the"
    say "certificate under Settings -> Privacy & Security -> Certificates -> Authorities."
    if [ -n "${LOGIN_FAILED}" ]; then
        exit 1
    fi
}

main "$@"
exit
}
