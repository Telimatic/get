#!/usr/bin/env python3
"""Run setup/telimatic-setup.sh against a temporary HOME and fake commands.

    python3 tests/team-setup-rig/run.py             # hermetic: no network, no sudo, no real step
    python3 tests/team-setup-rig/run.py --network   # also the REAL download from github.com/smallstep

Hermetic part (CI). `step`, `ssh-add`, `curl`, `uname`, `sysctl`, `id` and `sudo` are fakes on
PATH, and each case runs a copy of the script in which `/usr/bin/security` (the macOS keychain
tool) is a fake too. The fake `id` says uid 1000 and the fake `sudo` REFUSES and records every
call, so no case can reach the system trust store, whatever the script does: each case asserts
that sudo was never called, except the macOS CA cases, where sudo runs the fake `security`. The
session has no terminal (start_new_session), so no question is asked. It asserts:
  - macOS CA trust: "done" means TRUSTED, not only present: when the trust step fails (a
    cancelled dialog), the run fails, the certificate it added is taken out again, and the next
    run tries again; --uninstall removes the trust setting too (-t);
  - under sudo the step parts are skipped; --uninstall removes our step settings and leaves
    another CA's;
  - a download cut short (just after `main`, or mid-way) runs nothing;
  - --show writes nothing, and names the right archive and pin for each OS and processor;
  - --step writes step's defaults.json (the CA URL, and the root beside it, which is the
    certificate in ca/telimatic-internal-root-ca.crt), then signs in with the principal rule of
    services/ssh-ca/templates: `google` for a staff username, `google-outside` for `ext-`;
  - a second run changes nothing (same bytes, same mtime);
  - a defaults.json for another CA is left byte for byte, and no sign-in is tried;
  - the CA not answering, or step's sign-in failing, ends with exit 1;
  - a download whose SHA-256 is not the pin (a VALID archive holding a step) is refused and
    installs nothing; our own step copy at another version is replaced, not used;
  - the PATH line goes into the right login file, once (zsh: ~/.zprofile; bash: the first of
    ~/.bash_profile, ~/.bash_login, ~/.profile that exists);
  - bad --email or --user values are refused before anything is written; spaces around the
    email are trimmed;
  - static: both scripts pin the same step version, embed the same certificate as
    ca/telimatic-internal-root-ca.crt, and the .ps1 is ASCII and has
    no `exit` (inside `irm | iex` it would close the person's PowerShell window).
When `pwsh` is on PATH it also runs tests/team-setup-rig/pwsh-rig.ps1 (the .ps1's functions).

--network part (hand-run). The real curl downloads the pinned archives: this machine's Linux
build installs and `step version` reads back 0.31.0; the macOS arm64 and amd64 builds pass the
SHA-256 pin, but cannot run here, so the script stops at its version check of the unpacked file
and installs NOTHING (a file that does not run must not be left on PATH).

Prints each case; exits 1 on a failure.
"""
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
SH = os.path.join(REPO, "setup/telimatic-setup.sh")
PS1 = os.path.join(REPO, "setup/telimatic-setup.ps1")
ROLE_CERT = os.path.join(REPO, "ca/telimatic-internal-root-ca.crt")
CA_URL = "https://ssh-ca.telimatic.internal"

# The pins, read off the release's checksums.txt by hand (2026-11-17), NOT from the script:
# a test that read them from the script would pass whatever the script says.
PINS = {
    ("Darwin", "arm64"): ("step_darwin_0.31.0_arm64.tar.gz", "91963c7c1ef6654dda61ff2f99cff2b8e95efce198d8c7b3532a00a8f253bf41"),
    ("Darwin", "x86_64"): ("step_darwin_0.31.0_amd64.tar.gz", "4b928a936e9d2ff3bfa6f7638003a9e46c702a27cf515169c6e5996ade8cd23e"),
    ("Linux", "aarch64"): ("step_linux_0.31.0_arm64.tar.gz", "9937964c7d47de47a511cd775bd07101b8ee9854db210abd402c69093f0a6fd4"),
    ("Linux", "x86_64"): ("step_linux_0.31.0_amd64.tar.gz", "a7e13726efa8782f3d5459174dacf602ab3514b9431f2d42a6a75950b7685e5f"),
}

FAKE_STEP = r"""#!/bin/sh
# A fake smallstep CLI: the four calls telimatic-setup.sh makes, and nothing else.
case "$1" in
  version) echo "Smallstep CLI/0.31.0 (fake/rig)"; echo "Release Date: rig" ;;
  path)    echo "${STEPPATH:-$HOME/.step}" ;;
  ca)      [ "$2" = "health" ] || { echo "fake step: unexpected: $*" >&2; exit 99; }
           exit "${FAKE_CA_HEALTH_RC:-0}" ;;
  ssh)     [ "$2" = "login" ] || { echo "fake step: unexpected: $*" >&2; exit 99; }
           printf '%s\n' "$@" > "$FAKE_LOG_DIR/step-login"
           [ "${FAKE_LOGIN_RC:-0}" = 0 ] && : > "$FAKE_LOG_DIR/agent-has-cert"
           exit "${FAKE_LOGIN_RC:-0}" ;;
  *)       echo "fake step: unexpected: $*" >&2; exit 99 ;;
esac
"""

FAKE_SSH_ADD = r"""#!/bin/sh
[ "$1" = "-l" ] || { echo "fake ssh-add: unexpected: $*" >&2; exit 99; }
if [ -f "$FAKE_LOG_DIR/agent-has-cert" ]; then
  echo "256 SHA256:rig sam@example.org (ECDSA-CERT)"
else
  echo "The agent has no identities."; exit 1
fi
"""

# Writes FAKE_CURL_BODY to the -o file and records the URL (the last argument).
# Writes FAKE_CURL_BODY (a VALID tar.gz holding step_0.31.0/bin/step, a fake step) to the -o
# file: a script that skipped its SHA-256 stop would unpack and install it.
FAKE_CURL = r"""#!/bin/sh
out=""
while [ "$#" -gt 1 ]; do
  [ "$1" = "-o" ] && { out="$2"; shift; }
  shift
done
printf '%s\n' "$1" >> "$FAKE_LOG_DIR/curl-urls"
cp "$FAKE_CURL_BODY" "$out"
"""

FAKE_UNAME = r"""#!/bin/sh
case "$1" in
  -s) echo "${FAKE_UNAME_S:-Linux}" ;;
  -m) echo "${FAKE_UNAME_M:-x86_64}" ;;
  *)  exec /bin/uname "$@" ;;
esac
"""

FAKE_SYSCTL = "#!/bin/sh\necho 0\n"

FAKE_ID = r"""#!/bin/sh
[ "$1" = "-u" ] && { echo "${FAKE_UID:-1000}"; exit 0; }
exec /usr/bin/id "$@"
"""

# Records every call. Refuses, unless the case allows it (the macOS CA cases, whose privileged
# command is the fake security). `sudo -k` (drop the cached password) always succeeds.
FAKE_SUDO = r"""#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_LOG_DIR/sudo"
[ "$1" = "-k" ] && exit 0
[ "${FAKE_SUDO_ALLOW:-0}" = 1 ] || { echo "fake sudo: refused: $*" >&2; exit 1; }
exec "$@"
"""

# The macOS keychain tool, as trusted_cert_add.c orders it: add-trusted-cert ADDS the certificate,
# THEN saves its trust; FAKE_TRUST_RC=1 makes the second step fail (a cancelled dialog).
FAKE_SECURITY = r"""#!/bin/sh
kc="$FAKE_LOG_DIR/kc"; mkdir -p "$kc"
printf '%s\n' "$*" >> "$FAKE_LOG_DIR/security"
case "$1" in
  find-certificate) [ -f "$kc/present" ] && echo "SHA-256 hash: $FAKE_FP"; exit 0 ;;
  verify-cert)      [ -f "$kc/trusted" ] ;;
  add-trusted-cert) : > "$kc/present"
                    if [ "${FAKE_TRUST_RC:-0}" = 0 ]; then : > "$kc/trusted"; exit 0; fi
                    echo "SecTrustSettingsSetTrustSettings: The authorization was canceled by the user." >&2; exit 1 ;;
  delete-certificate) rm -f "$kc/present"
                    case " $* " in *" -t "*) rm -f "$kc/trusted" ;; esac; exit 0 ;;
  *) echo "fake security: unexpected: $*" >&2; exit 99 ;;
esac
"""

ROLE_FP = subprocess.run(["openssl", "x509", "-in", ROLE_CERT, "-noout", "-fingerprint", "-sha256"],
                         capture_output=True, text=True).stdout.strip().split("=")[-1].replace(":", "")

CASES_MADE = []


class Case:
    """One temporary HOME, a log directory for the fakes, and a fake bin directory."""

    def __init__(self, root, step=True, uname=None, curl=True, allow_sudo=False):
        self.root = root
        self.home = os.path.join(root, "home")
        self.logs = os.path.join(root, "logs")
        self.bin = os.path.join(root, "bin")
        self.tmp = os.path.join(root, "tmp")
        for d in (self.home, self.logs, self.bin, self.tmp):
            os.makedirs(d)
        fakes = {"ssh-add": FAKE_SSH_ADD, "sysctl": FAKE_SYSCTL, "id": FAKE_ID, "sudo": FAKE_SUDO,
                 "security": FAKE_SECURITY}
        if step:
            fakes["step"] = FAKE_STEP
        if curl:
            fakes["curl"] = FAKE_CURL
        if uname:
            fakes["uname"] = FAKE_UNAME
        for name, body in fakes.items():
            self.write_exec(os.path.join(self.bin, name), body)
        # The script under test, with only the keychain tool's absolute path changed.
        self.script = os.path.join(root, "telimatic-setup.sh")
        with open(SH) as f:
            text = f.read()
        with open(self.script, "w") as f:
            f.write(text.replace("/usr/bin/security", os.path.join(self.bin, "security")))
        archive = os.path.join(root, "fake-archive.tar.gz")
        with tarfile.open(archive, "w:gz") as t:
            info = tarfile.TarInfo("step_0.31.0/bin/step")
            body = FAKE_STEP.encode()
            info.size, info.mode = len(body), 0o755
            t.addfile(info, io.BytesIO(body))
        self.allow_sudo = allow_sudo
        CASES_MADE.append(self)
        self.env = {
            "HOME": self.home,
            "PATH": self.bin + ":/usr/bin:/bin",
            "SHELL": "/bin/zsh",
            "TMPDIR": self.tmp,
            "TZ": "UTC",
            "LANG": "C",
            "FAKE_LOG_DIR": self.logs,
            "SSH_AUTH_SOCK": os.path.join(root, "agent.sock"),
            "FAKE_CURL_BODY": archive,
            "FAKE_FP": ROLE_FP,
        }
        if allow_sudo:
            self.env["FAKE_SUDO_ALLOW"] = "1"
        if uname:
            self.env["FAKE_UNAME_S"], self.env["FAKE_UNAME_M"] = uname

    @staticmethod
    def write_exec(path, body):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(body)
        os.chmod(path, 0o755)

    def run(self, *args, **extra_env):
        env = dict(self.env, **extra_env)
        # start_new_session: no controlling terminal, so the script asks nothing (as in CI).
        # The timeout is a hang guard only: every fake answers at once.
        return subprocess.run(["bash", self.script, *args], env=env, capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, start_new_session=True, timeout=120)

    def run_stdin(self, text, *args):
        # The `curl | bash -s` shape: the script (or a prefix of it) on standard input.
        return subprocess.run(["bash", "-s", "--", *args], input=text, env=self.env, capture_output=True,
                              text=True, start_new_session=True, timeout=120)

    def log(self, name):
        p = os.path.join(self.logs, name)
        if not os.path.exists(p):
            return []
        with open(p) as f:
            return f.read().splitlines()

    def kc(self, name):
        return os.path.exists(os.path.join(self.logs, "kc", name))

    def files(self):
        out = []
        for d, _, names in os.walk(self.home):
            out += [os.path.relpath(os.path.join(d, n), self.home) for n in names]
        return sorted(out)

    def read(self, rel):
        p = os.path.join(self.home, rel)
        if not os.path.exists(p):
            return b"<missing>"
        with open(p, "rb") as f:
            return f.read()

    def login_argv(self):
        p = os.path.join(self.logs, "step-login")
        if not os.path.exists(p):
            return None
        with open(p) as f:
            return f.read().splitlines()

    def curl_urls(self):
        p = os.path.join(self.logs, "curl-urls")
        if not os.path.exists(p):
            return []
        with open(p) as f:
            return f.read().splitlines()


def role_cert():
    with open(ROLE_CERT, "rb") as f:
        return f.read()


def out_of(r):
    return f"exit {r.returncode}\n--- stdout\n{r.stdout}\n--- stderr\n{r.stderr}"


def case_show_writes_nothing(root):
    c = Case(root)
    r = c.run("--show", "--email", "Jane@Example.org", "--user", "ext-jane")
    return [
        (r.returncode == 0, "--show exits 0\n" + out_of(r)),
        (c.files() == [], f"--show writes nothing in HOME (found {c.files()})"),
        ("step ssh login jane@example.org --provisioner google-outside --principal ext-jane" in r.stdout,
         "--show names the sign-in, lower-cased email, google-outside for an ext- username\n" + r.stdout),
        (c.login_argv() is None, "--show does not sign in"),
        ("nothing was changed" in r.stdout, "--show says it changed nothing"),
    ]


def case_show_names_the_pinned_archive(root):
    checks = []
    for (s, m), (name, sha) in PINS.items():
        c = Case(os.path.join(root, f"{s}-{m}"), step=False, uname=(s, m))
        r = c.run("--show")
        checks.append((r.returncode == 0 and name in r.stdout and sha in r.stdout,
                       f"--show on {s}/{m} names {name} and its pin {sha}\n" + out_of(r)))
        checks.append((c.curl_urls() == [], f"--show on {s}/{m} downloads nothing"))
    c = Case(os.path.join(root, "unknown"), step=False, uname=("Linux", "riscv64"))
    r = c.run("--show")
    checks.append(("NO pinned build" in r.stdout, "--show on an unknown processor says there is no pinned build\n" + out_of(r)))
    return checks


def case_step_writes_settings_and_signs_in(root):
    c = Case(root)
    r = c.run("--step", "--email", "Sam@Example.org", "--user", "sam")
    checks = [(r.returncode == 0, "--step exits 0\n" + out_of(r))]
    try:
        defaults = json.loads(c.read(".step/config/defaults.json"))
    except (OSError, ValueError) as e:
        return checks + [(False, f"defaults.json is not readable JSON: {e}")]
    root_path = os.path.join(c.home, ".step/certs/telimatic-internal-root-ca.crt")
    checks += [
        (defaults == {"ca-url": CA_URL, "root": root_path}, f"defaults.json is the CA URL and the root path: {defaults}"),
        (c.read(".step/certs/telimatic-internal-root-ca.crt") == role_cert(),
         "the root step trusts is byte for byte ca/telimatic-internal-root-ca.crt"),
        (c.login_argv() == ["ssh", "login", "sam@example.org", "--provisioner", "google", "--principal", "sam"],
         f"step ssh login with the lower-cased email, provisioner google, principal sam: {c.login_argv()}"),
        ("Sign-in: done" in r.stdout, "the sign-in is read back from ssh-add -l"),
        (not any(f.startswith((".zprofile", ".profile", ".bash_profile")) for f in c.files()),
         f"a step already on PATH changes no login file: {c.files()}"),
    ]
    return checks


def case_outside_person_uses_google_outside(root):
    c = Case(root)
    r = c.run("--step", "--email", "jdoe@example.org", "--user", "ext-jdoe")
    return [(r.returncode == 0 and c.login_argv() == ["ssh", "login", "jdoe@example.org", "--provisioner", "google-outside", "--principal", "ext-jdoe"],
             f"an ext- username signs in through google-outside: {c.login_argv()}\n" + out_of(r))]


def case_second_run_changes_nothing(root):
    c = Case(root)
    r1 = c.run("--step", "--no-login")
    paths = [os.path.join(c.home, p) for p in (".step/config/defaults.json", ".step/certs/telimatic-internal-root-ca.crt")]
    if r1.returncode != 0 or not all(os.path.exists(p) for p in paths):
        return [(False, "first run did not write step's settings\n" + out_of(r1))]
    # Backdate both files, so a rewrite on the second run shows as a new mtime.
    for p in paths:
        os.utime(p, ns=(1_000_000_000, 1_000_000_000))
    before = [(open(p, "rb").read(), os.stat(p).st_mtime_ns) for p in paths]
    r2 = c.run("--step", "--no-login")
    after = [(open(p, "rb").read(), os.stat(p).st_mtime_ns) for p in paths]
    return [
        (r2.returncode == 0, "second run exits 0\n" + out_of(r2)),
        (before == after, "second run rewrites neither file (same bytes, same mtime)"),
        ("already point at" in r2.stdout, "second run says the settings are already there\n" + r2.stdout),
        (c.login_argv() is None, "--no-login does not sign in"),
    ]


def case_other_ca_left_alone(root):
    c = Case(root)
    other = b'{\n  "ca-url": "https://ca.example.org",\n  "root": "/somewhere/root.crt"\n}\n'
    os.makedirs(os.path.join(c.home, ".step/config"))
    with open(os.path.join(c.home, ".step/config/defaults.json"), "wb") as f:
        f.write(other)
    r = c.run("--step", "--email", "sam@example.org", "--user", "sam")
    return [
        (r.returncode == 0, "exits 0\n" + out_of(r)),
        (c.read(".step/config/defaults.json") == other, "another CA's defaults.json is left byte for byte"),
        (c.login_argv() is None, "no sign-in against another CA's settings"),
        (f"--ca-url {CA_URL} --root" in r.stdout, "it prints the sign-in with --ca-url and --root instead\n" + r.stdout),
    ]


def case_ca_unreachable_fails(root):
    c = Case(root)
    r = c.run("--step", "--email", "sam@example.org", "--user", "sam", FAKE_CA_HEALTH_RC="1")
    return [
        (r.returncode == 1, "the CA not answering ends with exit 1\n" + out_of(r)),
        (c.login_argv() is None, "no sign-in is tried when the CA does not answer"),
        ("WARP" in r.stdout, "it tells the person to turn on WARP"),
    ]


def case_login_failure_fails(root):
    c = Case(root)
    r = c.run("--step", "--email", "sam@example.org", "--user", "sam", FAKE_LOGIN_RC="1")
    return [
        (r.returncode == 1, "a failed step ssh login ends with exit 1\n" + out_of(r)),
        ("Sign-in FAILED" in r.stdout, "it says the sign-in failed"),
    ]


def case_checksum_mismatch_installs_nothing(root):
    c = Case(root, step=False, uname=("Darwin", "arm64"))
    r = c.run("--step", "--no-login")
    name = PINS[("Darwin", "arm64")][0]
    return [
        (r.returncode != 0, "a download that is not the pinned archive fails the run\n" + out_of(r)),
        ("SHA-256 MISMATCH" in r.stderr, "it names the SHA-256 mismatch"),
        (c.curl_urls() == [f"https://github.com/smallstep/cli/releases/download/v0.31.0/{name}"],
         f"it fetched the pinned release's macOS arm64 archive: {c.curl_urls()}"),
        (c.files() == [], f"nothing is installed, no login file is changed: {c.files()}"),
    ]


def case_path_line_goes_in_once(root):
    checks = []
    # Ours, from an earlier run, but not on this PATH: the line goes into the login file once.
    c = Case(os.path.join(root, "zsh"), step=False)
    Case.write_exec(os.path.join(c.home, ".local/bin/step"), FAKE_STEP)
    r1 = c.run("--step", "--no-login")
    r2 = c.run("--step", "--no-login")
    zprofile = c.read(".zprofile").decode() if os.path.exists(os.path.join(c.home, ".zprofile")) else ""
    checks += [
        (r1.returncode == 0 and r2.returncode == 0, "two runs exit 0\n" + out_of(r1) + out_of(r2)),
        (zprofile.count('export PATH="$HOME/.local/bin:$PATH"') == 1, f"zsh: ~/.zprofile carries the PATH line once:\n{zprofile}"),
    ]
    # bash with an existing ~/.profile: the line goes there, and no ~/.bash_profile appears
    # (bash would then stop reading ~/.profile).
    c = Case(os.path.join(root, "bash"), step=False)
    Case.write_exec(os.path.join(c.home, ".local/bin/step"), FAKE_STEP)
    with open(os.path.join(c.home, ".profile"), "w") as f:
        f.write("# the person's own\n")
    r = c.run("--step", "--no-login", SHELL="/bin/bash")
    profile = c.read(".profile").decode()
    checks += [
        (r.returncode == 0, "bash run exits 0\n" + out_of(r)),
        (profile.startswith("# the person's own\n") and 'export PATH="$HOME/.local/bin:$PATH"' in profile,
         f"bash: the line is appended to the existing ~/.profile:\n{profile}"),
        (not os.path.exists(os.path.join(c.home, ".bash_profile")), "bash: no ~/.bash_profile is created"),
    ]
    return checks


def case_bad_input_refused(root):
    checks = []
    for args, why in [(["--email", "not-an-email", "--user", "sam"], "an email without @"),
                      (["--email", "sam@example.org"], "an email with no username"),
                      (["--email", "sam@example.org", "--user", "Sam;rm"], "a username with other characters"),
                      (["--email", "sam x@example.org", "--user", "sam"], "an email with a space inside"),
                      (["--email", "sam@x@example.org", "--user", "sam"], "an email with two @")]:
        c = Case(os.path.join(root, str(len(checks))))
        r = c.run("--step", *args)
        checks.append((r.returncode != 0 and c.files() == [] and c.login_argv() is None,
                       f"{why} is refused before anything is written\n" + out_of(r)))
    return checks


def case_email_is_trimmed(root):
    c = Case(root)
    r = c.run("--step", "--email", "  Sam@Example.org ", "--user", " sam ")
    return [(r.returncode == 0 and c.login_argv() == ["ssh", "login", "sam@example.org", "--provisioner", "google", "--principal", "sam"],
             f"spaces around the email and the username are trimmed: {c.login_argv()}\n" + out_of(r))]


def case_macos_trust_refused(root):
    """M1: the trust step fails (a cancelled dialog). The run fails, the certificate this run
    added is taken out, and the next run does not call it done."""
    c = Case(root, uname=("Darwin", "arm64"), allow_sudo=True)
    r1 = c.run("--ca-only", "--yes", FAKE_TRUST_RC="1")
    present_after_1 = c.kc("present")
    r2 = c.run("--ca-only", "--yes", FAKE_TRUST_RC="1")
    adds = [l for l in c.log("security") if l.startswith("add-trusted-cert")]
    return [
        (r1.returncode != 0 and "NOT trusted" in r1.stderr, "a refused trust step fails the run and says NOT trusted\n" + out_of(r1)),
        (not present_after_1 and not c.kc("trusted"), "the certificate the run added is taken out again (no untrusted copy stays)"),
        ("already trusted" not in r2.stdout and r2.returncode != 0 and len(adds) == 2,
         f"the next run does not call it done and tries again ({len(adds)} add-trusted-cert calls)\n" + out_of(r2)),
    ]


def case_macos_trust_ok(root):
    c = Case(root, uname=("Darwin", "arm64"), allow_sudo=True)
    r1 = c.run("--ca-only", "--yes")
    r2 = c.run("--ca-only", "--yes")
    adds = [l for l in c.log("security") if l.startswith("add-trusted-cert")]
    return [
        (r1.returncode == 0 and c.kc("present") and c.kc("trusted"), "the certificate is added and trusted\n" + out_of(r1)),
        ("-k" in c.log("sudo"), f"sudo's cached password is dropped after the CA part: {c.log('sudo')}"),
        (r2.returncode == 0 and "already trusted" in r2.stdout and len(adds) == 1,
         f"a second run says already trusted and adds nothing ({len(adds)} add calls)\n" + out_of(r2)),
    ]


def case_macos_present_untrusted(root):
    c = Case(root, uname=("Darwin", "arm64"), allow_sudo=True)
    os.makedirs(os.path.join(c.logs, "kc"))
    open(os.path.join(c.logs, "kc", "present"), "w").close()
    r = c.run("--ca-only", "--yes")
    return [
        ("NOT trusted" in r.stdout and "already trusted, no change" not in r.stdout,
         "the plan names a present but untrusted certificate as NOT trusted\n" + out_of(r)),
        (r.returncode == 0 and c.kc("present") and c.kc("trusted"), "the run sets its trust"),
        (not any(l.startswith("delete-certificate") for l in c.log("security")), "a certificate that was there before is not deleted"),
    ]


def case_macos_uninstall_removes_trust(root):
    c = Case(root, uname=("Darwin", "arm64"), allow_sudo=True)
    r1 = c.run("--ca-only", "--yes")
    r2 = c.run("--uninstall")
    deletes = [l for l in c.log("security") if l.startswith("delete-certificate")]
    return [
        (r1.returncode == 0 and r2.returncode == 0, "install then --uninstall exit 0\n" + out_of(r1) + out_of(r2)),
        (len(deletes) == 1 and " -t " in f" {deletes[0]} ", f"--uninstall deletes with -t (the trust settings too): {deletes}"),
        (not c.kc("present") and not c.kc("trusted"), "after --uninstall the certificate and its trust are gone"),
    ]


def case_under_sudo_skips_step(root):
    c = Case(root, uname=("Darwin", "arm64"))
    r = c.run("--yes", "--email", "sam@example.org", "--user", "sam", FAKE_UID="0", SUDO_USER="sam")
    return [
        (r.returncode == 0 and "skipped under sudo" in r.stdout, "under sudo the plan says the step parts are skipped\n" + out_of(r)),
        (c.kc("trusted"), "the CA part still runs (as root, with no sudo)"),
        (not any(f.startswith(".step") or f.startswith(".local") for f in c.files()) and c.login_argv() is None,
         f"no step file is written and no sign-in is tried: {c.files()}"),
    ]


def case_uninstall_step_settings(root):
    checks = []
    c = Case(os.path.join(root, "ours"), uname=("Darwin", "arm64"))
    c.run("--step", "--no-login")
    r = c.run("--uninstall")
    checks.append((r.returncode == 0 and not os.path.exists(os.path.join(c.home, ".step/config/defaults.json"))
                   and not os.path.exists(os.path.join(c.home, ".step/certs/telimatic-internal-root-ca.crt")),
                   "--uninstall removes our step settings and root\n" + out_of(r)))
    c = Case(os.path.join(root, "other"), uname=("Darwin", "arm64"))
    other = b'{"ca-url": "https://ca.example.org"}\n'
    os.makedirs(os.path.join(c.home, ".step/config"))
    with open(os.path.join(c.home, ".step/config/defaults.json"), "wb") as f:
        f.write(other)
    r = c.run("--uninstall")
    checks.append((r.returncode == 0 and c.read(".step/config/defaults.json") == other,
                   "--uninstall leaves another CA's defaults.json byte for byte\n" + out_of(r)))
    return checks


def case_own_step_at_other_version_is_replaced(root):
    c = Case(root, step=False)
    Case.write_exec(os.path.join(c.home, ".local/bin/step"), FAKE_STEP.replace("0.31.0", "0.30.0"))
    r = c.run("--show")
    return [("download step_linux_0.31.0" in r.stdout and "use " + os.path.join(c.home, ".local/bin/step") not in r.stdout,
             "our own step at 0.30.0 is replaced by the pinned 0.31.0, not used\n" + out_of(r))]


def case_cut_download_runs_nothing(root):
    """L1: a prefix of the script on standard input (the `curl | bash` shape) runs nothing: cut
    just after the last `main` (which would otherwise run main with NO options: an install in
    place of the --show asked for), and cut in the middle."""
    checks = []
    with open(SH) as f:
        full = f.read()
    at = full.rindex('main "$@"') + len("main")
    for i, cut in enumerate((full[:at], full[:at + 1], full[:len(full) // 2])):
        c = Case(os.path.join(root, str(i)))
        r = c.run_stdin(cut, "--show")
        checks.append(("Telimatic internal root CA" not in r.stdout and c.files() == [] and c.log("sudo") == [],
                       f"a download cut at byte {len(cut)} of {len(full)} runs nothing\n" + out_of(r)))
    c = Case(os.path.join(root, "full"))
    r = c.run_stdin(full, "--show")
    checks.append((r.returncode == 0 and "nothing was changed" in r.stdout, "the whole script on standard input runs --show\n" + out_of(r)))
    return checks


def case_static_pins_agree(root):
    sh = open(SH).read()
    ps1_bytes = open(PS1, "rb").read()
    ps1 = ps1_bytes.decode("ascii", errors="replace")
    role = role_cert().decode()
    role_b64 = "".join(l for l in role.splitlines() if l and not l.startswith("-----"))
    sh_pem = re.search(r"<<'PEM' \|\| true\n(.*?)\nPEM\n", sh, re.S)
    ps1_b64 = re.search(r"\$TelimaticCertBase64 = @'\n(.*?)\n'@", ps1, re.S)
    sh_ver = re.search(r'^STEP_VERSION="([^"]+)"', sh, re.M)
    ps1_ver = re.search(r"^\$TelimaticStepVersion = '([^']+)'", ps1, re.M)
    sh_fp = re.search(r'^EXPECTED_FP="([^"]+)"', sh, re.M)
    ps1_fp = re.search(r"^\$TelimaticExpectedFingerprint = '([^']+)'", ps1, re.M)
    fp = subprocess.run(["openssl", "x509", "-in", ROLE_CERT, "-noout", "-fingerprint", "-sha256"],
                        capture_output=True, text=True).stdout.strip().split("=")[-1].replace(":", "")
    return [
        (sh_pem is not None and sh_pem.group(1) + "\n" == role, "the .sh embeds ca/telimatic-internal-root-ca.crt"),
        (ps1_b64 is not None and ps1_b64.group(1).replace("\n", "") == role_b64, "the .ps1 embeds ca/telimatic-internal-root-ca.crt"),
        (sh_fp is not None and sh_fp.group(1).replace(" ", "") == fp and ps1_fp is not None and ps1_fp.group(1) == fp,
         f"both scripts pin the certificate's SHA-256 {fp}"),
        (sh_ver is not None and ps1_ver is not None and sh_ver.group(1) == ps1_ver.group(1) == "0.31.0",
         "both scripts pin step 0.31.0"),
        (all(b < 0x80 for b in ps1_bytes), "the .ps1 is ASCII only (Windows PowerShell 5.1 reads a BOM-less file as ANSI)"),
        (not [l for l in ps1.splitlines() if not l.lstrip().startswith("#") and re.search(r"(^|[;{}(]|\belse)\s*exit\b", l.strip(), re.I)],
         "the .ps1 never calls exit (inside irm | iex it closes the window)"),
        (subprocess.run(["bash", "-n", SH]).returncode == 0, "bash -n parses the .sh"),
    ]


def case_pwsh(root):
    if shutil.which("pwsh") is None:
        print("SKIP  pwsh is not on PATH: run tests/team-setup-rig/pwsh-rig.ps1 by hand (README.md, \"Team setup\")")
        return []
    r = subprocess.run(["pwsh", "-NoProfile", "-File", os.path.join(HERE, "pwsh-rig.ps1")],
                       capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=300)
    return [(r.returncode == 0, "pwsh-rig.ps1 passes\n" + out_of(r))]


def case_network(root):
    checks = []
    native = {"x86_64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}.get(os.uname().machine)
    c = Case(os.path.join(root, "linux"), step=False, curl=False)
    r = c.run("--step", "--no-login")
    v = subprocess.run([os.path.join(c.home, ".local/bin/step"), "version"], capture_output=True, text=True) \
        if os.path.exists(os.path.join(c.home, ".local/bin/step")) else None
    checks.append((native is not None and r.returncode == 0 and v is not None and v.stdout.startswith("Smallstep CLI/0.31.0 "),
                   f"the real Linux {native} archive downloads, matches its pin, installs and runs\n" + out_of(r)))
    for m in ("arm64", "x86_64"):
        c = Case(os.path.join(root, f"darwin-{m}"), step=False, uname=("Darwin", m), curl=False)
        r = c.run("--step", "--no-login")
        checks.append(("step: SHA-256 matches the pin" in r.stdout and r.returncode != 0
                       and "not Smallstep CLI/0.31.0. Nothing was installed." in r.stderr and c.files() == [],
                       f"the real macOS {m} archive matches its pin; it cannot run here, so the run stops at the "
                       "version check of the UNPACKED file and installs nothing\n" + out_of(r)))
    return checks


CASES = [case_show_writes_nothing, case_show_names_the_pinned_archive, case_step_writes_settings_and_signs_in,
         case_outside_person_uses_google_outside, case_second_run_changes_nothing, case_other_ca_left_alone,
         case_ca_unreachable_fails, case_login_failure_fails, case_checksum_mismatch_installs_nothing,
         case_path_line_goes_in_once, case_bad_input_refused, case_email_is_trimmed, case_macos_trust_refused,
         case_macos_trust_ok, case_macos_present_untrusted, case_macos_uninstall_removes_trust,
         case_under_sudo_skips_step, case_uninstall_step_settings, case_own_step_at_other_version_is_replaced,
         case_cut_download_runs_nothing, case_static_pins_agree, case_pwsh]


def main():
    cases = CASES + ([case_network] if "--network" in sys.argv[1:] else [])
    failed = total = 0
    with tempfile.TemporaryDirectory(prefix="team-setup-rig-") as tmp:
        for fn in cases:
            first = len(CASES_MADE)
            checks = fn(os.path.join(tmp, fn.__name__))
            # No case but the macOS CA ones may call sudo at all: the fake refuses and records it.
            calls = [l for c in CASES_MADE[first:] if not c.allow_sudo for l in c.log("sudo")]
            if CASES_MADE[first:]:
                checks.append((calls == [], f"{fn.__name__}: no privileged call (sudo) was made: {calls}"))
            for ok, msg in checks:
                total += 1
                if not ok:
                    failed += 1
                print(("PASS  " if ok else "FAIL  ") + (msg if not ok else msg.splitlines()[0]))
    print(f"{total - failed}/{total} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
