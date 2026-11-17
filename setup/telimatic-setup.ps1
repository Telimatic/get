<#
.SYNOPSIS
    Set up a teammate's Windows machine for Telimatic in one command: trust the Telimatic
    internal root CA, install and set up the step CLI, and sign in for an SSH certificate.

.DESCRIPTION
    Everything:   irm https://get.telimatic.com/setup/telimatic-setup.ps1 | iex
    Just look:    & ([scriptblock]::Create((irm https://get.telimatic.com/setup/telimatic-setup.ps1))) -Show
    Remove:       & ([scriptblock]::Create((irm https://get.telimatic.com/setup/telimatic-setup.ps1))) -Uninstall

    (`irm ... | iex` cannot pass arguments. The scriptblock form is how you give it a switch
    without saving the file first. If you have saved it:
    `powershell -ExecutionPolicy Bypass -File .\telimatic-setup.ps1 -Show`.)

    It does four things, in this order, and prints them all before it changes anything:
      1. CA TRUST. The Telimatic internal root CA goes into CurrentUser\Root (LocalMachine\Root
         when run as Administrator), so *.telimatic.internal sites open in Chrome and Edge.
      2. STEP. The smallstep CLI. A `step` already on PATH (winget, scoop) is used as it is.
         Otherwise ONE pinned release is downloaded from github.com/smallstep/cli, checked
         against the SHA-256 written below, and installed to
         %LOCALAPPDATA%\Programs\step\step.exe, which goes on your user PATH.
      3. STEP SETTINGS. step's defaults ($(step path)\config\defaults.json): the CA URL
         https://ssh-ca.telimatic.internal and this certificate as its root.
      4. SIGN-IN. It asks your Telimatic Google email and your username (the `username` of your
         row in the ansible `users` list; NOT always the part of your email before the @) and
         runs `step ssh login`. A browser opens for the Google sign-in. An `ext-` username (an
         outside person) signs in through `google-outside`, any other through `google`.
         step puts the certificate into the Windows OpenSSH agent (the `ssh-agent` service).
         Windows ships that service DISABLED and only an Administrator can turn it on: the
         script prints the one command for that. Run the script itself WITHOUT elevation (an
         elevated window may run as another account, and then step, its settings and the
         certificate would go to that account); run only the printed command as Administrator.

    Options: -Show (print the plan, change nothing), -CaOnly (part 1 only), -Step (parts 2-4),
    -Uninstall, -NoLogin, -Email <you@telimatic.com>, -User <username>, -Yes (no pause).
    Run it again at any time: a part that is already done says so and changes nothing.

    WHAT YOU ARE TRUSTING. This is a PUBLIC certificate, the CA's public half. The private key
    that signs with it lives only in Oracle Cloud vaults and is not in this script, not in any
    repository, and not on any server. The certificate carries a CRITICAL X.509 name
    constraint permitting DNS:telimatic.internal and nothing else, which means a correct TLS
    client REJECTS anything this CA signs for any other name: it cannot vouch for google.com,
    your bank, or your employer's real domain.

    FIREFOX IS NOT COVERED. Set security.enterprise_roots.enabled to true in about:config so
    it reads the Windows store, or import the certificate by hand.

    THIS FILE IS ASCII ONLY, AND NEVER CALLS `exit`. Windows PowerShell 5.1 reads a saved .ps1
    with no byte-order mark as ANSI, where the UTF-8 bytes of a dash include a byte it reads as
    a closing double quote, which breaks the string around it. And `exit` inside
    `irm | iex` or a scriptblock closes the person's whole PowerShell window (measured in
    pwsh 7.4); every stop here is a `return` or a `throw`.

    THE WHOLE SCRIPT IS ONE SCRIPTBLOCK, `& { ... } @args`. Its functions and variables stay in
    the block's own scope, so `irm | iex` leaves nothing behind in the person's session, and a
    download cut short is a parse error (an unclosed brace), so it runs nothing.
#>

& {
[CmdletBinding()]
param(
    [switch]$Uninstall,
    [switch]$Show,
    [switch]$CaOnly,
    [switch]$Step,
    [switch]$NoLogin,
    [string]$Email = '',
    [string]$User = '',
    [switch]$Yes
)

# ---------------------------------------------------------------------------
# THE PIN: the SHA-256 fingerprint of the certificate embedded below, written
# out separately so that the two disagreeing stops the script.
#
# BE HONEST ABOUT WHAT THAT BUYS. Anyone who could swap the certificate below
# could swap this line too, so the pin is NOT protection against a hostile copy
# of this script: the HTTPS origin you fetched it from is what protects you
# there. What it catches is a truncated download, a mangled paste, and a
# certificate quietly replaced in a diff nobody read. It also gives you a value
# to compare out of band, against the copy in the Telimatic ansible repository
# at roles/internal-ca-trust/files/telimatic-internal-root-ca.crt.
# ---------------------------------------------------------------------------
$TelimaticExpectedFingerprint = '4A107FF153744DA64C70DD19F51EE9F6221906986FE3FBD113AE180195C26C79'

# The base64 body of the PEM IS the certificate's DER encoding.
$TelimaticCertBase64 = @'
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
'@

# ---------------------------------------------------------------------------
# THE STEP RELEASE. One version, and the SHA-256 of each Windows archive this
# script may install, copied from that release's checksums.txt
# (https://github.com/smallstep/cli/releases/download/v0.31.0/checksums.txt).
# How those values were checked, and how to move to a new version: the same
# block in telimatic-setup.sh. A download whose SHA-256 differs is refused.
# ---------------------------------------------------------------------------
$TelimaticStepVersion = '0.31.0'
$TelimaticStepSha256 = @{
    'amd64' = '3b8dc1245fb1dffe3b57bf10cac9b3da9808ed42f7274f869085e1086214d0f4'
    'arm64' = 'f5be7139b78db9d051274c029cc3aefa7d87c16d4867a430eddfebdc8689d922'
}
$TelimaticStepCaUrl = 'https://ssh-ca.telimatic.internal'

function Stop-TelimaticSetup([string]$Message) {
    Write-Host "ERROR: $Message" -ForegroundColor Red
    throw "telimatic-setup stopped: $Message"
}

function Test-TelimaticOnWindows {
    if (Test-Path variable:IsWindows) { return [bool]$IsWindows }   # $IsWindows exists only on PS 6+
    return $true                                                     # Windows PowerShell 5.1
}

# ==========================================================================
# The certificate: decode it and CHECK IT BEFORE ANYTHING TRUSTS IT.
# ==========================================================================
function Get-TelimaticCert {
    try {
        $der  = [Convert]::FromBase64String(($TelimaticCertBase64 -replace '\s', ''))
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (,$der)
    } catch {
        Stop-TelimaticSetup "the certificate embedded in this script could not be decoded: your copy is damaged. Download it again. ($($_.Exception.Message))"
    }
    # Computed from the raw DER rather than read off a property: GetCertHashString()
    # with no argument is SHA-1 on every Windows PowerShell 5.1, and the SHA-256
    # overload exists only on newer runtimes. This works on both.
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $fp = ($sha256.ComputeHash($cert.RawData) | ForEach-Object { $_.ToString('X2') }) -join ''
    if ($fp -ne $TelimaticExpectedFingerprint) {
        Stop-TelimaticSetup @"
FINGERPRINT MISMATCH - refusing to trust anything.
  this script pins : $TelimaticExpectedFingerprint
  the certificate  : $fp
Your copy of this script has been altered or truncated. Do not run it. Fetch it again
from the original link, and if it still mismatches, tell whoever gave you the link.
"@
    }

    # The name constraint is the reason this is safe to install, so it is CHECKED
    # rather than assumed. .NET has no strongly typed NameConstraints class, so the
    # extension is located by OID (2.5.29.30), its critical flag is read, and the
    # permitted name is found in its raw bytes as ASCII, which is exactly how it is
    # encoded in an IA5String.
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
    Write-Host ("  SHA-256      : " + $fp)
    Write-Host ("  limited to   : " + $constraintText)
    Write-Host ''
    if (-not $constrained) {
        Write-Host '  WARNING: this certificate does not carry a name constraint permitting only' -ForegroundColor Yellow
        Write-Host '  telimatic.internal, which means trusting it would let it vouch for ANY' -ForegroundColor Yellow
        Write-Host '  website. That is not what this CA is supposed to be. Stop and ask.' -ForegroundColor Yellow
        Stop-TelimaticSetup 'the certificate has no name constraint.'
    }
    return $cert
}

function Get-TelimaticCertPem {
    $body = (($TelimaticCertBase64 -split '\s+') | Where-Object { $_ }) -join "`n"
    return "-----BEGIN CERTIFICATE-----`n$body`n-----END CERTIFICATE-----`n"
}

# ==========================================================================
# Part 1: CA trust. LocalMachine when elevated, CurrentUser when not. Writing
# to LocalMachine\Root without elevation throws an access-denied that reads
# like a bug; picking the store from the token the script runs under does not.
# ==========================================================================
function Test-TelimaticElevated {
    if (-not (Test-TelimaticOnWindows)) { return $false }
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Open-TelimaticRootStore([string]$Location, [string]$Mode) {
    $s = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', $Location)
    try { $s.Open($Mode) } catch {
        Stop-TelimaticSetup "could not open the $Location\Root certificate store for $Mode. $($_.Exception.Message)"
    }
    return $s
}

function Test-TelimaticCaPresent($Cert, [string]$Location) {
    $store = Open-TelimaticRootStore $Location 'ReadOnly'
    try {
        return [bool]($store.Certificates | Where-Object { $_.Thumbprint -eq $Cert.Thumbprint })
    } finally { $store.Close() }
}

function Install-TelimaticCa($Cert, [string]$Location) {
    if (Test-TelimaticCaPresent $Cert $Location) {
        Write-Host "CA trust: already in $Location\Root, nothing to do."
        return
    }
    if ($Location -eq 'CurrentUser') {
        Write-Host 'CA trust: installing for THIS USER only (CurrentUser\Root). Windows asks you to confirm.'
    }
    $store = Open-TelimaticRootStore $Location 'ReadWrite'
    try { $store.Add($Cert) } finally { $store.Close() }
    # Read the write back rather than trusting that Add() returning is the same as
    # the certificate being there.
    if (-not (Test-TelimaticCaPresent $Cert $Location)) {
        Stop-TelimaticSetup "the certificate does not appear in $Location\Root after adding it."
    }
    Write-Host "CA trust: installed into $Location\Root. Close and reopen Chrome or Edge."
}

function Uninstall-TelimaticCa($Cert, [string]$Location) {
    # An install from an elevated window went to LocalMachine\Root. Without elevation it cannot be
    # removed from there (reading it needs no elevation), so say so instead of failing on it.
    if ($Location -eq 'CurrentUser' -and (Test-TelimaticCaPresent $Cert 'LocalMachine')) {
        Stop-TelimaticSetup 'the certificate is installed for all users (LocalMachine\Root). Run -Uninstall from an Administrator PowerShell.'
    }
    if (-not (Test-TelimaticCaPresent $Cert $Location)) {
        Write-Host "CA trust: not in $Location\Root, nothing to remove."
        return
    }
    $store = Open-TelimaticRootStore $Location 'ReadWrite'
    try { $store.Remove($Cert) } finally { $store.Close() }
    # Read the write back: a removal can be undone by Group Policy, which pushes
    # certificates into this store and re-applies them.
    if (Test-TelimaticCaPresent $Cert $Location) {
        Stop-TelimaticSetup "the certificate is still in $Location\Root after removing it. If this machine is domain-joined, Group Policy may be pushing it: ask IT."
    }
    Write-Host "CA trust: removed from $Location\Root. Close and reopen Chrome or Edge."
}

# ==========================================================================
# Part 2: the step CLI.
# ==========================================================================
function Get-TelimaticStepHome {
    return (Join-Path $env:LOCALAPPDATA 'Programs\step')
}

function Get-TelimaticStepVersionLine([string]$Exe) {
    # 'Continue' in this function only: Windows PowerShell 5.1 turns a native command's stderr
    # into a terminating error under 'Stop' when stderr is redirected.
    $ErrorActionPreference = 'Continue'
    try { $out = & $Exe version 2>$null } catch { return '' }
    if ($null -eq $out) { return '' }
    return [string](@($out)[0])
}

function Test-TelimaticSmallstep([string]$Exe) {
    return (Get-TelimaticStepVersionLine $Exe).StartsWith('Smallstep CLI/')
}

function Test-TelimaticPinnedStep([string]$Exe) {
    return (Get-TelimaticStepVersionLine $Exe).StartsWith("Smallstep CLI/$TelimaticStepVersion ")
}

# The step to use, or '': a `step` on PATH that is not ours (winget, scoop: the person's, used as it
# is), else OUR copy, but only when it is the pinned version: when the pin moves (a security fix),
# the next run installs the new one.
function Find-TelimaticStep {
    $ours = ''
    if (Test-TelimaticOnWindows) { $ours = Join-Path (Get-TelimaticStepHome) 'step.exe' }
    $onPath = Get-Command step -CommandType Application -ErrorAction SilentlyContinue |
        Where-Object { -not $ours -or $_.Source -ine $ours } | Select-Object -First 1
    if ($onPath) {
        if (-not (Test-TelimaticSmallstep $onPath.Source)) {
            Stop-TelimaticSetup "the program named step at $($onPath.Source) is not the smallstep CLI. Remove or rename it, then run this script again."
        }
        return $onPath.Source
    }
    if ($ours -and (Test-Path -LiteralPath $ours) -and (Test-TelimaticPinnedStep $ours)) { return $ours }
    return ''
}

# @{ Name = <archive>; Sha256 = <hex> } for a processor architecture, or $null.
function Get-TelimaticStepAsset([string]$Architecture) {
    switch ($Architecture) {
        'AMD64' { $a = 'amd64' }
        'ARM64' { $a = 'arm64' }
        default { return $null }
    }
    return @{ Name = "step_windows_$($TelimaticStepVersion)_$a.zip"; Sha256 = $TelimaticStepSha256[$a] }
}

function Get-TelimaticArchitecture {
    # A 32-bit PowerShell on 64-bit Windows says x86 here and names the real one in ...W6432.
    if ($env:PROCESSOR_ARCHITEW6432) { return $env:PROCESSOR_ARCHITEW6432 }
    return $env:PROCESSOR_ARCHITECTURE
}

# Checks the archive at $Archive against the pin and unpacks it under $WorkDir. Returns the
# unpacked step.exe; nothing is unpacked unless the SHA-256 matches.
function Expand-TelimaticStepArchive([string]$Archive, [string]$Sha256, [string]$WorkDir) {
    $got = (Get-FileHash -Algorithm SHA256 -LiteralPath $Archive).Hash.ToLowerInvariant()
    if ($got -ne $Sha256) {
        Stop-TelimaticSetup @"
SHA-256 MISMATCH for $(Split-Path -Leaf $Archive): refusing to install it.
  this script pins : $Sha256
  the download     : $got
Nothing was installed. Run the script again later; if it still mismatches, tell whoever gave you the link.
"@
    }
    Write-Host "step: SHA-256 matches the pin ($Sha256)."
    $unpack = Join-Path $WorkDir 'unpack'
    Expand-Archive -LiteralPath $Archive -DestinationPath $unpack -Force
    $exe = Join-Path (Join-Path (Join-Path $unpack "step_$TelimaticStepVersion") 'bin') 'step.exe'
    if (-not (Test-Path -LiteralPath $exe)) { Stop-TelimaticSetup "the archive holds no step_$TelimaticStepVersion\bin\step.exe. Nothing was installed." }
    return $exe
}

function Install-TelimaticStep {
    $asset = Get-TelimaticStepAsset (Get-TelimaticArchitecture)
    if (-not $asset) {
        Stop-TelimaticSetup "there is no pinned step build for this processor ($(Get-TelimaticArchitecture)). Install step yourself (https://smallstep.com/docs/step-cli/installation), then run this script again with -Step."
    }
    $url = "https://github.com/smallstep/cli/releases/download/v$TelimaticStepVersion/$($asset.Name)"
    $work = Join-Path ([IO.Path]::GetTempPath()) ('telimatic-setup-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    try {
        $archive = Join-Path $work $asset.Name
        Write-Host "step: downloading $url"
        # Windows PowerShell 5.1 may offer only TLS 1.0/1.1 by default; GitHub needs 1.2.
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $archive
        } catch {
            Stop-TelimaticSetup "the download of $url failed. Nothing was installed. ($($_.Exception.Message))"
        }
        $unpacked = Expand-TelimaticStepArchive $archive $asset.Sha256 $work
        # The unpacked file must run, and be the pinned version, BEFORE it goes in place: a file
        # that does not run must not be left on PATH.
        $version = Get-TelimaticStepVersionLine $unpacked
        if (-not $version.StartsWith("Smallstep CLI/$TelimaticStepVersion ")) {
            Stop-TelimaticSetup "the unpacked step answered 'step version' with '$version', not Smallstep CLI/$TelimaticStepVersion. Nothing was installed."
        }
        New-Item -ItemType Directory -Force -Path (Get-TelimaticStepHome) | Out-Null
        $exe = Join-Path (Get-TelimaticStepHome) 'step.exe'
        Copy-Item -LiteralPath $unpacked -Destination $exe -Force
    } finally {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
    # Read it back: the installed file is the pinned version.
    if (-not (Test-TelimaticPinnedStep $exe)) { Stop-TelimaticSetup "$exe does not answer Smallstep CLI/$TelimaticStepVersion after the install." }
    Write-Host "step: installed $exe ($version)."
    return $exe
}

function Test-TelimaticPathHas([string]$PathValue, [string]$Dir) {
    $want = $Dir.TrimEnd('\')
    foreach ($p in ($PathValue -split ';')) {
        if ($p.TrimEnd('\') -ieq $want) { return $true }
    }
    return $false
}

# The user PATH lives in HKCU\Environment as REG_EXPAND_SZ. [Environment]::SetEnvironmentVariable
# would read it EXPANDED and write it back as REG_SZ, which breaks every %VAR% in it; so it is
# read raw and written back with its kind, then one dummy variable is set and cleared through
# .NET, which broadcasts the change so new terminals see it.
function Add-TelimaticUserPath([string]$Dir) {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
    try {
        $raw = $key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if (Test-TelimaticPathHas $raw $Dir) { return $false }
        $new = if ($raw) { $raw.TrimEnd(';') + ';' + $Dir } else { $Dir }
        $key.SetValue('Path', $new, [Microsoft.Win32.RegistryValueKind]::ExpandString)
    } finally { $key.Close() }
    [Environment]::SetEnvironmentVariable('TELIMATIC_SETUP_PATH_CHANGED', '1', 'User')
    [Environment]::SetEnvironmentVariable('TELIMATIC_SETUP_PATH_CHANGED', $null, 'User')
    return $true
}

function Get-TelimaticUserPath {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $false)
    try { return [string]$key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) }
    finally { $key.Close() }
}

function Set-TelimaticStepPath([string]$Dir) {
    if (Add-TelimaticUserPath $Dir) {
        if (-not (Test-TelimaticPathHas (Get-TelimaticUserPath) $Dir)) {
            Stop-TelimaticSetup "$Dir is not on your user PATH after adding it."
        }
        Write-Host "step: added $Dir to your user PATH (new terminals)."
    }
    # This PowerShell, too: with `irm | iex` the script runs in it.
    if (-not (Test-TelimaticPathHas $env:Path $Dir)) { $env:Path = $env:Path.TrimEnd(';') + ';' + $Dir }
}

# ==========================================================================
# Part 3: step's settings, in the person's own step directory (`step path`).
# step checks the CA's TLS against the ONE root file it is given, never the
# Windows store, so part 1 does not reach it.
# ==========================================================================
function Get-TelimaticStepFiles([string]$StepDir) {
    if (-not [IO.Path]::IsPathRooted($StepDir)) {
        Stop-TelimaticSetup "'step path' did not answer an absolute directory ('$StepDir'), so this step is not the smallstep CLI; nothing written for step."
    }
    return @{
        Dir      = $StepDir
        Root     = Join-Path (Join-Path $StepDir 'certs') 'telimatic-internal-root-ca.crt'
        Defaults = Join-Path (Join-Path $StepDir 'config') 'defaults.json'
    }
}

# 'ours', 'other' (a defaults.json for another CA, or one we cannot read), or 'none'.
function Get-TelimaticStepDefaultsState($Files) {
    if (-not (Test-Path -LiteralPath $Files.Defaults)) { return 'none' }
    try {
        $json = [IO.File]::ReadAllText($Files.Defaults) | ConvertFrom-Json
    } catch { return 'other' }
    if ($json.'ca-url' -eq $TelimaticStepCaUrl) { return 'ours' }
    return 'other'
}

function Test-TelimaticStepConfigDone($Files) {
    if ((Get-TelimaticStepDefaultsState $Files) -ne 'ours') { return $false }
    if (-not (Test-Path -LiteralPath $Files.Root)) { return $false }
    return ([IO.File]::ReadAllText($Files.Root) -ceq (Get-TelimaticCertPem))
}

# Returns 'done', 'written' or 'other'.
function Set-TelimaticStepConfig($Files) {
    if (Test-TelimaticStepConfigDone $Files) {
        Write-Host "step settings: already point at $TelimaticStepCaUrl, nothing to do."
        return 'done'
    }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Files.Root) | Out-Null
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Files.Defaults) | Out-Null
    # WriteAllText with no encoding writes UTF-8 with NO byte-order mark; step's JSON
    # reader (Go) refuses a file that starts with one, which Set-Content -Encoding UTF8 writes.
    [IO.File]::WriteAllText($Files.Root, (Get-TelimaticCertPem))
    $state = Get-TelimaticStepDefaultsState $Files
    if ($state -eq 'other') {
        Write-Host "NOTE: $($Files.Defaults) already points step at another CA; it is left as it is."
        Write-Host "      Use --ca-url $TelimaticStepCaUrl --root `"$($Files.Root)`" on each step command instead."
        return 'other'
    }
    if ($state -eq 'ours') {
        $keys = @(([IO.File]::ReadAllText($Files.Defaults) | ConvertFrom-Json).PSObject.Properties).Count
        if ($keys -gt 2) {
            Copy-Item -LiteralPath $Files.Defaults -Destination ($Files.Defaults + '.bak') -Force
            Write-Host "NOTE: $($Files.Defaults) had more settings than ours; the old file is kept as $($Files.Defaults).bak."
        }
    }
    $json = [ordered]@{ 'ca-url' = $TelimaticStepCaUrl; 'root' = $Files.Root } | ConvertTo-Json
    [IO.File]::WriteAllText($Files.Defaults, $json + "`n")
    Write-Host "step settings: written to $($Files.Defaults) (CA $TelimaticStepCaUrl)."
    return 'written'
}

function Remove-TelimaticStepConfig($Files) {
    if ((Get-TelimaticStepDefaultsState $Files) -eq 'ours') {
        Remove-Item -LiteralPath $Files.Defaults, $Files.Root -Force -ErrorAction SilentlyContinue
        Write-Host "step settings: removed ($TelimaticStepCaUrl)."
    } else {
        Write-Host 'step settings: not ours, nothing to remove.'
    }
}

# ==========================================================================
# Part 4: sign in. The principal is your username from the `users` list, never
# derived from your email; an `ext-` username is an outside person and signs in
# through `google-outside` (services/ssh-ca/templates in the ansible repository).
# ==========================================================================
function Get-TelimaticProvisioner([string]$Username) {
    if ($Username.StartsWith('ext-')) { return 'google-outside' }
    return 'google'
}

function Test-TelimaticLoginInput([string]$Mail, [string]$Username) {
    if (-not $Mail -and -not $Username) { return }
    if ($Mail -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { Stop-TelimaticSetup "'$Mail' is not an email address." }
    if (-not $Username) { Stop-TelimaticSetup 'an email was given but no username: add -User <username>.' }
    if ($Username -cnotmatch '^[a-z0-9_-]+$') { Stop-TelimaticSetup "'$Username' is not a username (lower-case letters, digits, - and _ only)." }
}

function Get-TelimaticLoginCommand([string]$Mail, [string]$Username) {
    return "step ssh login $Mail --provisioner $(Get-TelimaticProvisioner $Username) --principal $Username"
}

# 'ready', 'sock' (SSH_AUTH_SOCK names one), 'start' (the service is there but
# not running), or 'missing' (no OpenSSH client).
function Get-TelimaticAgentState {
    if ($env:SSH_AUTH_SOCK) { return 'sock' }
    $svc = Get-Service ssh-agent -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') { return 'ready' }
    # Another agent on the same pipe (1Password's needs the service stopped).
    try {
        if ([IO.Directory]::GetFiles('\\.\pipe\') -contains '\\.\pipe\openssh-ssh-agent') { return 'ready' }
    } catch { }
    if ($svc) { return 'start' }
    return 'missing'
}

function Enable-TelimaticAgent {
    Set-Service ssh-agent -StartupType Automatic
    Start-Service ssh-agent
    if ((Get-Service ssh-agent).Status -ne 'Running') { Stop-TelimaticSetup 'the ssh-agent service did not start.' }
    Write-Host 'Sign-in: the Windows ssh-agent service is on (it starts with Windows from now on).'
}

function Invoke-TelimaticLogin([string]$Exe, [string]$Mail, [string]$Username) {
    $cmd = Get-TelimaticLoginCommand $Mail $Username
    # 'Continue' in this function only: Windows PowerShell 5.1 turns a native command's stderr
    # into a terminating error under 'Stop' when stderr is redirected (step and ssh-add below).
    # Every stop here is Stop-TelimaticSetup's throw, which does not depend on it.
    $ErrorActionPreference = 'Continue'
    & $Exe ca health *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Sign-in: $TelimaticStepCaUrl does not answer. Turn on WARP (Cloudflare One), then run:"
        Write-Host "  $cmd"
        return $false
    }
    $agent = Get-TelimaticAgentState
    if ($agent -eq 'start') {
        if (Test-TelimaticElevated) { Enable-TelimaticAgent }
        else {
            Write-Host 'Sign-in: the Windows ssh-agent service is off, and only an Administrator can turn it on.'
            Write-Host '  In an Administrator PowerShell, run once:'
            Write-Host '    Set-Service ssh-agent -StartupType Automatic; Start-Service ssh-agent'
            Write-Host "  Then, in this window: $cmd"
            return $false
        }
    } elseif ($agent -eq 'missing') {
        Write-Host 'Sign-in: the OpenSSH client is not installed. In an Administrator PowerShell, run once:'
        Write-Host '    Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0'
        Write-Host "  then run this script again, or: $cmd"
        return $false
    }
    Write-Host "Sign-in: $cmd"
    Write-Host '  A browser opens for the Google sign-in.'
    # Out-Host: a native command's output inside a function would otherwise become part of
    # the function's return value.
    & $Exe ssh login $Mail --provisioner (Get-TelimaticProvisioner $Username) --principal $Username | Out-Host
    if ($LASTEXITCODE -ne 0) {
        Write-Host ''
        Write-Host "Sign-in FAILED (step exit $LASTEXITCODE). The usual causes:"
        Write-Host '  - the CA names your real username in its error ("signs only the one principal X"): run again with -User X;'
        Write-Host '  - the 1Password SSH agent holds the agent pipe, and it cannot hold a certificate.'
        return $false
    }
    # Read it back: the agent must now hold a certificate.
    $keys = (& ssh-add -l 2>$null) -join "`n"
    if ($keys -notmatch '-CERT\)') {
        Write-Host "Sign-in: step finished, but 'ssh-add -l' lists no certificate. See docs/runbooks/ssh-certificates.md in the ansible repository."
        return $false
    }
    Write-Host 'Sign-in: done. The SSH agent holds your certificate. Log in with:'
    Write-Host "  ssh $Username@<host>.telimatic.internal"
    return $true
}

# ==========================================================================
# The plan: what each part would change, printed by -Show and before any change.
# ==========================================================================
function Write-TelimaticPlan($Cert, [string]$Mode, [string]$Location, [string]$StepExe, [string]$Mail, [string]$Username, [bool]$SkipLogin) {
    $onWindows = Test-TelimaticOnWindows
    Write-Host 'What this script does on this machine:'
    if ($Mode -ne 'step') {
        if (-not $onWindows) { Write-Host '  1. CA trust      : (Windows only; this is not Windows.)' }
        elseif (Test-TelimaticCaPresent $Cert $Location) { Write-Host "  1. CA trust      : already in $Location\Root, no change." }
        else { Write-Host "  1. CA trust      : add the certificate above to $Location\Root." }
    }
    if ($Mode -eq 'ca-only') { Write-Host ''; return }
    if ($StepExe) {
        Write-Host "  2. step          : use $StepExe ($(Get-TelimaticStepVersionLine $StepExe)), no download."
    } else {
        $asset = Get-TelimaticStepAsset (Get-TelimaticArchitecture)
        if ($asset) {
            Write-Host "  2. step          : download $($asset.Name) from github.com/smallstep/cli,"
            Write-Host "                     check its SHA-256 against $($asset.Sha256),"
            if ($onWindows) { Write-Host "                     install it to $(Get-TelimaticStepHome)\step.exe and put that folder on your user PATH." }
        } else {
            Write-Host "  2. step          : NO pinned build for this processor ($(Get-TelimaticArchitecture)): the script stops here."
        }
    }
    if ($StepExe) {
        $files = Get-TelimaticStepFiles ((& $StepExe path) | Select-Object -First 1)
        if (Test-TelimaticStepConfigDone $files) { Write-Host "  3. step settings : already point at $TelimaticStepCaUrl, no change." }
        elseif ((Get-TelimaticStepDefaultsState $files) -eq 'other') { Write-Host "  3. step settings : $($files.Defaults) points at another CA: left as it is." }
        else { Write-Host "  3. step settings : write $($files.Defaults) (ca-url $TelimaticStepCaUrl) and $($files.Root)." }
    } else {
        Write-Host "  3. step settings : write `$(step path)\config\defaults.json (ca-url $TelimaticStepCaUrl) and the root beside it."
    }
    if ($SkipLogin) { Write-Host '  4. sign-in       : skipped.' }
    elseif ($Mail) { Write-Host "  4. sign-in       : $(Get-TelimaticLoginCommand $Mail $Username)  (a browser opens)" }
    elseif ($Mode -eq 'show') { Write-Host '  4. sign-in       : ask your email and username, then run step ssh login (a browser opens).' }
    else { Write-Host '  4. sign-in       : skipped (no email given).' }
    if ($onWindows -and -not $SkipLogin) {
        switch (Get-TelimaticAgentState) {
            'start'   { Write-Host "                     ssh-agent service: off; $(if (Test-TelimaticElevated) { 'turn it on (Automatic) and start it.' } else { 'only an Administrator can turn it on; the script prints the command.' })" }
            'missing' { Write-Host '                     OpenSSH client: not installed; the script prints the Administrator command.' }
            default   { Write-Host '                     SSH agent: ready.' }
        }
    }
    Write-Host ''
}

function Test-TelimaticInteractive {
    try { return ([Environment]::UserInteractive -and -not [Console]::IsInputRedirected) } catch { return $false }
}

function Invoke-TelimaticSetup {
    param([switch]$Uninstall, [switch]$Show, [switch]$CaOnly, [switch]$Step, [switch]$NoLogin,
          [string]$Email = '', [string]$User = '', [switch]$Yes)
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'   # Windows PowerShell 5.1's download progress bar is very slow

    $mode = 'install'
    if ($Step)      { $mode = 'step' }
    if ($CaOnly)    { $mode = 'ca-only' }
    if ($Show)      { $mode = 'show' }
    if ($Uninstall) { $mode = 'uninstall' }

    $cert = Get-TelimaticCert
    $onWindows = Test-TelimaticOnWindows
    $location = if (Test-TelimaticElevated) { 'LocalMachine' } else { 'CurrentUser' }
    if ($location -eq 'LocalMachine' -and -not $Show) {
        Write-Host "NOTE: this window runs as Administrator, as the account $env:USERNAME. step, its settings and the"
        Write-Host '      SSH certificate go to THAT account. If it is not your own, stop (Ctrl-C) and run the script'
        Write-Host '      in a normal PowerShell; run only the ssh-agent command it prints as Administrator.'
        Write-Host ''
    }
    $Email = $Email.Trim().ToLowerInvariant()
    $User = $User.Trim()

    if ($mode -eq 'show') {
        Test-TelimaticLoginInput $Email $User
        Write-TelimaticPlan $cert $mode $location (Find-TelimaticStep) $Email $User ([bool]$NoLogin)
        Write-Host '-Show: nothing was changed.'
        return
    }
    if (-not $onWindows) {
        Stop-TelimaticSetup 'this script changes WINDOWS settings and cannot do anything on this operating system. Use telimatic-setup.sh instead: it covers macOS and Linux. (-Show works here.)'
    }
    if ($mode -eq 'uninstall') {
        Uninstall-TelimaticCa $cert $location
        $exe = Find-TelimaticStep
        if ($exe) {
            Remove-TelimaticStepConfig (Get-TelimaticStepFiles ((& $exe path) | Select-Object -First 1))
            if ($exe -eq (Join-Path (Get-TelimaticStepHome) 'step.exe')) {
                Write-Host "NOTE: step itself stays at $exe. To remove it too, delete $(Get-TelimaticStepHome) and take it off your user PATH."
            }
        }
        return
    }

    $skipLogin = [bool]$NoLogin -or $mode -eq 'ca-only'
    if (-not $skipLogin -and -not ($Email -and $User) -and (Test-TelimaticInteractive)) {
        Write-Host 'Sign-in: the last step gets you an SSH certificate. Press Enter on an empty line to skip it.'
        if (-not $Email) { $Email = (Read-Host '  Your Telimatic Google email (you@telimatic.com)').Trim().ToLowerInvariant() }
        if ($Email -and -not $User) {
            Write-Host '  Your username on our hosts is the `username` of your row in the ansible users list.'
            Write-Host '  It is not always the part of your email before the @. Ask in #engineering if unsure.'
            $User = (Read-Host '  Your username').Trim()
        }
        Write-Host ''
    }
    Test-TelimaticLoginInput $Email $User

    $stepExe = ''
    if ($mode -ne 'ca-only') { $stepExe = Find-TelimaticStep }
    Write-TelimaticPlan $cert $mode $location $stepExe $Email $User $skipLogin
    if (-not $Yes -and (Test-TelimaticInteractive)) {
        [void](Read-Host 'Press Enter to go on, or Ctrl-C to stop')
        Write-Host ''
    }

    if ($mode -ne 'step') { Install-TelimaticCa $cert $location }
    $loginOk = $true
    if ($mode -ne 'ca-only') {
        if ($stepExe) { Write-Host "step: using $stepExe ($(Get-TelimaticStepVersionLine $stepExe))." }
        else { $stepExe = Install-TelimaticStep }
        if ($stepExe -eq (Join-Path (Get-TelimaticStepHome) 'step.exe')) { Set-TelimaticStepPath (Get-TelimaticStepHome) }
        $files = Get-TelimaticStepFiles ((& $stepExe path) | Select-Object -First 1)
        $config = Set-TelimaticStepConfig $files
        if (-not $skipLogin) {
            if (-not $Email) {
                Write-Host 'Sign-in: skipped (no email given). Later, with WARP on:'
                Write-Host '  step ssh login <you>@telimatic.com --provisioner google --principal <your username>'
            } elseif ($config -eq 'other') {
                Write-Host 'Sign-in: skipped, because step''s settings point at another CA. With WARP on, run:'
                Write-Host "  $(Get-TelimaticLoginCommand $Email $User) --ca-url $TelimaticStepCaUrl --root `"$($files.Root)`""
            } else {
                $loginOk = Invoke-TelimaticLogin $stepExe $Email $User
            }
        }
    }
    Write-Host ''
    Write-Host 'Firefox keeps its own trust store and ignores Windows. Set'
    Write-Host 'security.enterprise_roots.enabled to true in about:config, or import the'
    Write-Host 'certificate under Settings -> Privacy & Security -> Certificates -> Authorities.'
    if (-not $loginOk) { Stop-TelimaticSetup 'the sign-in did not complete; the lines above say what to do.' }
}

Invoke-TelimaticSetup @PSBoundParameters
} @args
