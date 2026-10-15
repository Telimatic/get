# get.telimatic.com

Install scripts and public files for Telimatic teammates, served over GitHub Pages at
[get.telimatic.com](https://get.telimatic.com). Everything here is **public** — do not add
anything that is not meant to be world-readable and permanently cacheable.

> **Status, as of 2026-10-15: the Windows install works; macOS is still UNTESTED.** A teammate
> ran `install.ps1` on a real Windows PC on 2026-10-15 and reported that it worked. The macOS
> keychain path has not been run on a real Mac. `--show` / `-Show` is safe to run anywhere first —
> it only downloads and inspects the certificate and changes nothing on the machine. See "What
> was actually tested" below for the detail.

## What's here

| Path | What |
|---|---|
| `ca/telimatic-internal-root-ca.crt` | The Telimatic internal root CA's **public** certificate (no private key). |
| `ca/install.sh` | Trusts the CA on macOS and Linux. |
| `ca/install.ps1` | Trusts the CA on Windows. |
| `index.html` | The page at [get.telimatic.com](https://get.telimatic.com). |

## Trust the Telimatic internal root CA

Run once so `*.telimatic.internal` addresses (internal dashboards, monitoring, admin tools) open
in Chrome/Edge/Safari without a warning.

```sh
curl -fsSL https://get.telimatic.com/ca/install.sh | bash                      # install
curl -fsSL https://get.telimatic.com/ca/install.sh | bash -s -- --show         # look, change nothing
curl -fsSL https://get.telimatic.com/ca/install.sh | bash -s -- --uninstall    # remove
```

```powershell
irm https://get.telimatic.com/ca/install.ps1 | iex
& ([scriptblock]::Create((irm https://get.telimatic.com/ca/install.ps1))) -Show
& ([scriptblock]::Create((irm https://get.telimatic.com/ca/install.ps1))) -Uninstall
```

`irm … | iex` cannot pass arguments, which is why `-Show` and `-Uninstall` use the scriptblock
form.

### Firefox is not covered by either script

Firefox ships its own trust store and ignores the operating system's. Either set
`security.enterprise_roots.enabled` to `true` in `about:config`, which makes Firefox read the OS
store, or import the certificate by hand under **Settings → Privacy & Security → Certificates →
View Certificates → Authorities → Import**. Chrome, Edge and Safari read the OS store and need
nothing extra — except **Chrome on Linux**, which reads NSS (`~/.pki/nssdb`); `install.sh` handles
that too when `certutil` is installed.

## The certificate, and where it comes from

| | |
|---|---|
| Subject | `O = Telimatic, CN = Telimatic Internal Root CA` |
| Key | ECDSA P-384 |
| Valid | 2026-07-10 → **2126-07-10** |
| SHA-256 | `4A:10:7F:F1:53:74:4D:A6:4C:70:DD:19:F5:1E:E9:F6:22:19:06:98:6F:E3:FB:D1:13:AE:18:01:95:C2:6C:79` |
| Name constraints | **critical**, `Permitted: DNS:telimatic.internal` |

The version-controlled source of truth is
`roles/internal-ca-trust/files/telimatic-internal-root-ca.crt` in the `Telimatic/ansible`
repository — the same file the `internal-ca-trust` role installs on every Telimatic VM. **Edit the
certificate there, not here**; this repository's copy is what the scripts fetch and pin against,
and both scripts' pinned fingerprint changes in the same commit as any cert rotation.

Neither script embeds the certificate. Each downloads it fresh, every run, from
`https://get.telimatic.com/ca/telimatic-internal-root-ca.crt` — the same origin that served the
script — and refuses to install anything unless the download's SHA-256 fingerprint equals the
value pinned inside the script. Prove the committed copy matches the pin:

```sh
openssl x509 -in ca/telimatic-internal-root-ca.crt -noout -fingerprint -sha256 -subject -enddate
bash ca/install.sh --show
```

Both print the fingerprint in the table above. The CI workflow in this repository
(`.github/workflows/ci.yml`) checks this on every push and pull request, so a cert swap that
forgets to update the pin in both scripts fails CI.

## What the fingerprint pin does and does not do

Each script carries the expected SHA-256 separately from the download and refuses to install
anything if they disagree. **Anyone who could alter what `get.telimatic.com` serves could alter
the pinned value in the script too**, since both are served from the same origin — this is not
protection against a hostile origin. The HTTPS connection to `get.telimatic.com`, and whatever
review gates a change to this repository, is what protects you there.

What the pin does catch: a truncated download, a mangled copy-and-paste if you saved a script by
hand, and a certificate quietly swapped in a diff nobody read. It also gives you a value to
compare out of band — against the table above, or against a colleague reading it back.

## What this does and does not give away

**This is the safe kind of private CA, and the reason is one X.509 extension.**

The root carries **critical** name constraints permitting `DNS:telimatic.internal` and nothing
else. A TLS client that trusts it will accept certificates this CA signs **only** for names ending
in `telimatic.internal`. It cannot vouch for `google.com`, your bank, your personal email, or your
employer's real domain — a certificate from this CA for any of those fails to verify. Because the
constraint is marked critical, a client that does not understand name constraints must **reject**
the certificate rather than ignore the constraint.

**What you are accepting, stated plainly.** Whoever controls this CA's private key can mint a
certificate for any `*.telimatic.internal` name and, if they can also get your traffic to point at
their server, read or alter your connection to Telimatic internal services. That is the same trust
you already place in those services. It does not extend past `telimatic.internal`.

**Where the key lives.** Only in three regional Oracle Cloud vaults. It is not in these scripts,
not in this repository, and not on any VM. The certificate here is the public half.

**If you leave.** Run the script with `--uninstall` (or `-Uninstall`). Both scripts read the
removal back and say so if something — an MDM profile on a managed Mac, Group Policy on a
domain-joined PC — is putting the certificate back.

## What was actually tested, and what was not

| Path | Verified |
|---|---|
| `--show` / `-Show` downloads, verifies the pin, prints subject/expiry/fingerprint/name constraint | yes — on Linux (shell) and against a local test server standing in for `get.telimatic.com` |
| Fingerprint pin rejects a corrupted / non-certificate download | yes — watched it refuse |
| Fingerprint pin rejects a **valid but different** CA with the same subject | yes — watched it refuse, naming both fingerprints |
| `shellcheck` on `install.sh` | yes — clean |
| **macOS keychain install/uninstall** | **NO — not exercised on a real Mac. Run `--show` first, then install on one Mac and confirm before telling the team.** |
| Windows certificate-store **install** | yes — a teammate ran `irm https://get.telimatic.com/ca/install.ps1 \| iex` on a real Windows PC on 2026-10-15 and reported that it worked (reported in Slack; whether the shell was elevated, and the PowerShell version, were not recorded) |
| **Windows certificate-store uninstall** (`-Uninstall`) | **NO — not exercised on a real Windows machine.** |
| `install.ps1`'s download/decode/pin-check path on real Windows | yes — the 2026-10-15 install above ran it end to end. PowerShell 7 on another OS is not exercised. |

## Hosting

This is a GitHub Pages site (`main` branch, root), custom domain `get.telimatic.com`, DNS-only
CNAME to `telimatic.github.io` (no Cloudflare proxy — GitHub issues the certificate for the custom
domain itself and needs the proxy off to do it).

**No large files.** GitHub Pages is not built for multi-GB artifacts — soft-capped around 1GB per
site and each file should stay well under 100MB. If Telimatic ever needs to publish something
sizable from this domain, that goes to object storage (S3 or an OCI bucket) behind its own
route, not into this repository.
