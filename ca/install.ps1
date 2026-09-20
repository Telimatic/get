<#
.SYNOPSIS
    Make this Windows machine trust the Telimatic internal root CA, so
    *.telimatic.internal sites open in Chrome and Edge without a warning.

.DESCRIPTION
    Run it:        irm https://get.telimatic.com/ca/install.ps1 | iex
    Remove it:     & ([scriptblock]::Create((irm https://get.telimatic.com/ca/install.ps1))) -Uninstall
    Just look:     & ([scriptblock]::Create((irm https://get.telimatic.com/ca/install.ps1))) -Show

    (`irm ... | iex` cannot pass arguments. The scriptblock form above is how you
    give it a switch without saving the file first. If you have saved it:
    `powershell -ExecutionPolicy Bypass -File .\install.ps1 -Uninstall`.)

    WHAT YOU ARE TRUSTING. This is a PUBLIC certificate — the CA's public half.
    The private key that signs with it lives only in Oracle Cloud vaults and is
    not in this script, not in any repository, and not on any server. The
    certificate carries a CRITICAL X.509 name constraint permitting
    DNS:telimatic.internal and nothing else, which means a correct TLS client
    REJECTS anything this CA signs for any other name: it cannot vouch for
    google.com, your bank, or your employer's real domain.

    WHERE THE CERTIFICATE COMES FROM. This script does NOT embed the
    certificate. It downloads it fresh, every run, from
    https://get.telimatic.com/ca/telimatic-internal-root-ca.crt — the same
    origin that served this script — and REFUSES to trust it unless its SHA-256
    fingerprint equals the value pinned below.

    WHERE IT LANDS. Run as Administrator it installs to LocalMachine\Root, which
    covers every user on the machine. Run without elevation it installs to
    CurrentUser\Root, which covers only you — that works for Chrome and Edge and
    needs no admin rights.

    FIREFOX IS NOT COVERED. Firefox ships its own trust store and ignores
    Windows'. Set security.enterprise_roots.enabled to true in about:config so it
    reads the Windows store, or import the certificate by hand under Settings ->
    Privacy & Security -> Certificates -> View Certificates -> Authorities.

    Idempotent: running it twice is a no-op the second time.
#>

[CmdletBinding()]
param(
    [switch]$Uninstall,
    [switch]$Show
)

$ErrorActionPreference = 'Stop'

$CertUrl = 'https://get.telimatic.com/ca/telimatic-internal-root-ca.crt'

# ---------------------------------------------------------------------------
# THE PIN — the SHA-256 fingerprint the downloaded certificate must match,
# written out separately from the download so that the two disagreeing stops
# the script.
#
# BE HONEST ABOUT WHAT THAT BUYS. Anyone who could alter what get.telimatic.com
# serves at the certificate URL could alter this script (served from the same
# origin) too, so the pin is NOT protection against a hostile origin — the
# HTTPS connection to get.telimatic.com, and whatever review gates a change to
# that repository, is what protects you there. What it catches is a truncated
# download, a mangled paste if you saved this file by hand, and a certificate
# quietly replaced in a change nobody read. It also gives you a value to
# compare out of band, against the copy in the Telimatic ansible repository at
# roles/internal-ca-trust/files/telimatic-internal-root-ca.crt.
# ---------------------------------------------------------------------------
$ExpectedFingerprint = '4A107FF153744DA64C70DD19F51EE9F6221906986FE3FBD113AE180195C26C79'

function Fail([string]$Message) {
    Write-Host "ERROR: $Message" -ForegroundColor Red
    exit 1
}

# --------------------------------------------------------------------------
# DOWNLOAD the certificate and CHECK IT BEFORE ANYTHING TRUSTS IT. Nothing
# below this point trusts $cert until the fingerprint compares equal.
# --------------------------------------------------------------------------
Write-Host "Downloading the certificate from $CertUrl ..."
$tmpCertPath = Join-Path ([System.IO.Path]::GetTempPath()) ("telimatic-internal-root-ca-" + [System.Guid]::NewGuid().ToString() + ".crt")
try {
    Invoke-WebRequest -Uri $CertUrl -OutFile $tmpCertPath -UseBasicParsing | Out-Null
} catch {
    Fail "could not download the certificate from $CertUrl. Check your network connection and try again. ($($_.Exception.Message))"
}

try {
    $der = [System.IO.File]::ReadAllBytes($tmpCertPath)
    $pemText = [System.Text.Encoding]::ASCII.GetString($der)
    if ($pemText -match '-----BEGIN CERTIFICATE-----') {
        # PEM text (this is what get.telimatic.com serves) — decode the base64 body.
        $b64 = ($pemText -replace '-----BEGIN CERTIFICATE-----', '') -replace '-----END CERTIFICATE-----', ''
        $der = [Convert]::FromBase64String(($b64 -replace '\s', ''))
    }
    # else: assume it is already raw DER and use the downloaded bytes as-is.
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (,$der)
} catch {
    Fail "what was downloaded from $CertUrl is not a readable certificate. It may have been truncated, or the origin may be serving something unexpected. Do not proceed — try again, and if it still fails, tell whoever gave you the link. ($($_.Exception.Message))"
} finally {
    Remove-Item -Path $tmpCertPath -Force -ErrorAction SilentlyContinue
}

# Computed from the raw DER rather than read off a property: GetCertHashString()
# with no argument is SHA-1 on every Windows PowerShell 5.1, and the SHA-256
# overload exists only on newer runtimes. This works on both.
$sha256 = [System.Security.Cryptography.SHA256]::Create()
$actualFingerprint = ($sha256.ComputeHash($cert.RawData) | ForEach-Object { $_.ToString('X2') }) -join ''

if ($actualFingerprint -ne $ExpectedFingerprint) {
    Fail @"
FINGERPRINT MISMATCH - refusing to trust anything.
  this script pins          : $ExpectedFingerprint
  the downloaded certificate: $actualFingerprint
The certificate served at $CertUrl does not match what this script expects.
Do not run further. Try again in case of a transient/corrupted download; if it
still mismatches, tell whoever gave you the link before doing anything else.
"@
}

# --------------------------------------------------------------------------
# The name constraint is the reason this is safe to install, so it is CHECKED
# rather than assumed. .NET has no strongly typed NameConstraints class, so the
# extension is located by OID (2.5.29.30), its critical flag is read, and the
# permitted name is found in its raw bytes as ASCII — which is exactly how it is
# encoded in an IA5String.
# --------------------------------------------------------------------------
$nc = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.30' }
$constrained = $false
$constraintText = 'NONE'
if ($nc) {
    $raw = [System.Text.Encoding]::ASCII.GetString($nc.RawData)
    if ($raw -match 'telimatic\.internal') {
        $constrained = $true
        $constraintText = 'DNS:telimatic.internal' + $(if ($nc.Critical) { ' (critical)' } else { ' (NOT critical)' })
    } else {
        $constraintText = 'present, but does not permit telimatic.internal'
    }
}

Write-Host 'Telimatic internal root CA'
Write-Host ("  subject      : " + $cert.Subject)
Write-Host ("  expires      : " + $cert.NotAfter.ToString('yyyy-MM-dd'))
Write-Host ("  SHA-256      : " + $actualFingerprint)
Write-Host ("  limited to   : " + $constraintText)

if (-not $constrained) {
    Write-Host ''
    Write-Host '  WARNING: this certificate does not carry a name constraint permitting only' -ForegroundColor Yellow
    Write-Host '  telimatic.internal, which means trusting it would let it vouch for ANY' -ForegroundColor Yellow
    Write-Host '  website. That is not what this CA is supposed to be. Stop and ask.' -ForegroundColor Yellow
    exit 1
}
Write-Host ''

if ($Show) { exit 0 }

# --------------------------------------------------------------------------
# WINDOWS ONLY, AND THE GUARD IS HERE BECAUSE THE ALTERNATIVE IS A CORE DUMP.
#
# PowerShell 7 runs on Linux and macOS, where the .NET `Root` store is READ-ONLY
# — opening it ReadWrite does not return an error a script can report, it throws
# out of the runtime and the process aborts with an unhandled
# TargetInvocationException and no useful message. Measured in a
# mcr.microsoft.com/powershell container. Everything above this line is
# platform-independent and still runs there, which is why -Show works anywhere.
# --------------------------------------------------------------------------
$onWindows = $true
if (Test-Path variable:IsWindows) { $onWindows = $IsWindows }   # $IsWindows exists only on PS 6+
if (-not $onWindows) {
    Fail "this script installs into the WINDOWS certificate store and cannot do anything on this operating system. Use install.sh instead — it covers macOS and Linux. (-Show works here and is what you just saw.)"
}

# --------------------------------------------------------------------------
# LocalMachine when elevated, CurrentUser when not. Writing to LocalMachine\Root
# without elevation throws an access-denied that reads like a bug; picking the
# store from the token the script is actually running under does not.
# --------------------------------------------------------------------------
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$elevated  = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$location  = if ($elevated) { 'LocalMachine' } else { 'CurrentUser' }

if (-not $elevated) {
    Write-Host 'Not running as Administrator — installing for THIS USER only (CurrentUser\Root).'
    Write-Host 'That covers Chrome and Edge for you. Re-run from an elevated PowerShell to'
    Write-Host 'cover every user on this machine.'
    Write-Host ''
}

function Open-RootStore([string]$Location, [string]$Mode) {
    # Wrapped so an access-denied or a policy-locked store is reported as a
    # sentence rather than as a .NET stack trace.
    $s = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', $Location)
    try { $s.Open($Mode) } catch {
        Fail "could not open the $Location\Root certificate store for $Mode. $($_.Exception.Message)"
    }
    return $s
}

if ($Uninstall) {
    $store = Open-RootStore $location 'ReadWrite'
    try {
        $present = $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
        if (-not $present) {
            Write-Host "Not present in $location\Root — nothing to remove."
        } else {
            $store.Remove($cert)
            Write-Host "Removed from $location\Root."
        }
    } finally { $store.Close() }

    # Read the write back: a removal can be undone by Group Policy, which pushes
    # certificates into this store and re-applies them. A return code alone would
    # not show that.
    $verify = Open-RootStore $location 'ReadOnly'
    try {
        if ($verify.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }) {
            Fail "the certificate is still in $location\Root after removing it. If this machine is domain-joined, Group Policy may be pushing it — ask IT."
        }
    } finally { $verify.Close() }

    Write-Host 'Close and reopen Chrome or Edge for this to take effect.'
    exit 0
}

$store = Open-RootStore $location 'ReadWrite'
try {
    if ($store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }) {
        Write-Host "Already trusted in $location\Root — nothing to do."
        Write-Host '(If Chrome still warns, close and reopen it: it caches trust decisions.)'
        exit 0
    }
    $store.Add($cert)
} finally { $store.Close() }

# Read the write back rather than trusting that Add() returning is the same as
# the certificate being there.
$verify = Open-RootStore $location 'ReadOnly'
try {
    if (-not ($verify.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint })) {
        Fail "the certificate does not appear in $location\Root after adding it."
    }
} finally { $verify.Close() }

Write-Host "Installed into $location\Root."
Write-Host 'Close and reopen Chrome or Edge for this to take effect.'
Write-Host ''
Write-Host 'Firefox keeps its own trust store and ignores Windows. Set'
Write-Host 'security.enterprise_roots.enabled to true in about:config, or import the'
Write-Host 'certificate under Settings -> Privacy & Security -> Certificates -> Authorities.'
