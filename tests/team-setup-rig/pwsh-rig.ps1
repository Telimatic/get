# Checks setup/telimatic-setup.ps1 with pwsh, on any OS (run.py runs it when pwsh is on
# PATH; by hand in a container: README.md, "Team setup").
#
#   pwsh -NoProfile -File tests/team-setup-rig/pwsh-rig.ps1 [-WindowsZip <step_windows_0.31.0_amd64.zip>]
#
# It loads the script's FUNCTIONS and its Telimatic* settings from the parsed file (nothing in the
# script runs), then checks: the archive name and pin per processor; the provisioner rule; the
# PEM it writes is ca/telimatic-internal-root-ca.crt; step's settings (no byte-order mark,
# a second call changes nothing, another CA's file is left alone); a download that is not the
# pinned archive installs nothing; with -WindowsZip, the real archive passes its pin and unpacks
# step.exe. Then it runs the whole script: -Show exits 0 and changes nothing; on a non-Windows
# OS any other mode stops with an error and no change; and neither `irm | iex` nor the
# scriptblock form closes the PowerShell session (the script never calls exit).
# The Windows-only parts (the certificate stores, the user PATH in the registry, the ssh-agent
# service, a real step ssh login) are NOT covered: they need Windows.
param([string]$WindowsZip = '')

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$script = Join-Path $repo 'setup/telimatic-setup.ps1'
$roleCert = Join-Path $repo 'ca/telimatic-internal-root-ca.crt'
$script:failed = 0
$script:total = 0

function Check([bool]$Ok, [string]$Message) {
    $script:total++
    if ($Ok) { Write-Host "PASS  $(($Message -split "`n")[0])" } else { $script:failed++; Write-Host "FAIL  $Message" }
}

# Load the functions and the Telimatic* assignments from the parsed file, without running it.
$errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($script, [ref]$null, [ref]$errs)
Check ($errs.Count -eq 0) "the .ps1 parses ($($errs.Count) errors)"
# The script is one `& { ... } @args` block, so they are found at any depth.
$defs = $ast.FindAll({ param($n)
    ($n -is [System.Management.Automation.Language.FunctionDefinitionAst]) -or
    (($n -is [System.Management.Automation.Language.AssignmentStatementAst]) -and ($n.Left.Extent.Text -like '$Telimatic*')) }, $true)
foreach ($st in $defs) { . ([scriptblock]::Create($st.Extent.Text)) }
Check (@($defs | Where-Object { $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] }).Count -gt 20) "the script's functions are found ($(@($defs).Count) definitions)"
$exits = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ExitStatementAst] }, $true)
Check (@($exits).Count -eq 0) "the script has no exit statement (inside irm | iex it closes the window): $(@($exits).Count)"

$tmp = Join-Path ([IO.Path]::GetTempPath()) ('team-setup-pwsh-rig-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    # --- the archive and pin per processor (values from the release's checksums.txt, by hand)
    $a = Get-TelimaticStepAsset 'AMD64'
    Check ($a.Name -eq 'step_windows_0.31.0_amd64.zip' -and $a.Sha256 -eq '3b8dc1245fb1dffe3b57bf10cac9b3da9808ed42f7274f869085e1086214d0f4') 'AMD64: step_windows_0.31.0_amd64.zip and its pin'
    $a = Get-TelimaticStepAsset 'ARM64'
    Check ($a.Name -eq 'step_windows_0.31.0_arm64.zip' -and $a.Sha256 -eq 'f5be7139b78db9d051274c029cc3aefa7d87c16d4867a430eddfebdc8689d922') 'ARM64: step_windows_0.31.0_arm64.zip and its pin'
    Check ($null -eq (Get-TelimaticStepAsset 'x86')) 'x86: no pinned build'

    # --- the provisioner rule (services/ssh-ca/templates)
    Check ((Get-TelimaticProvisioner 'sam') -eq 'google') 'a staff username signs in through google'
    Check ((Get-TelimaticProvisioner 'ext-jdoe') -eq 'google-outside') 'an ext- username signs in through google-outside'
    $refused = $false
    try { Test-TelimaticLoginInput 'sam@example.org' 'Sam' } catch { $refused = $true }
    Check $refused 'an upper-case username is refused'
    $refused = $false
    try { Test-TelimaticLoginInput 'sam@example.org' '' } catch { $refused = $true }
    Check $refused 'an email with no username is refused'

    # --- the PEM step trusts is the role's certificate
    $rolePem = ([IO.File]::ReadAllText($roleCert)) -replace "`r`n", "`n"
    Check ((Get-TelimaticCertPem) -eq $rolePem) "the PEM written for step is ca/telimatic-internal-root-ca.crt"

    # --- step's settings
    $files = Get-TelimaticStepFiles (Join-Path $tmp 'step-home')
    $r1 = Set-TelimaticStepConfig $files
    $bytes = [IO.File]::ReadAllBytes($files.Defaults)
    $json = [IO.File]::ReadAllText($files.Defaults) | ConvertFrom-Json
    Check ($r1 -eq 'written') "first call writes step's settings ($r1)"
    Check ($bytes[0] -eq [byte][char]'{') 'defaults.json starts with { (no byte-order mark)'
    Check ($json.'ca-url' -eq 'https://ssh-ca.telimatic.internal' -and $json.root -eq $files.Root) 'defaults.json holds the CA URL and the root path'
    Check (([IO.File]::ReadAllText($files.Root)) -eq $rolePem) 'the root file is the certificate'
    $past = [datetime]'2001-01-01'
    (Get-Item $files.Defaults).LastWriteTime = $past
    $r2 = Set-TelimaticStepConfig $files
    Check ($r2 -eq 'done' -and (Get-Item $files.Defaults).LastWriteTime -eq $past) "a second call changes nothing ($r2)"

    $other = Get-TelimaticStepFiles (Join-Path $tmp 'other-home')
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $other.Defaults) | Out-Null
    $otherText = "{`n  `"ca-url`": `"https://ca.example.org`"`n}`n"
    [IO.File]::WriteAllText($other.Defaults, $otherText)
    $r3 = Set-TelimaticStepConfig $other
    Check ($r3 -eq 'other' -and [IO.File]::ReadAllText($other.Defaults) -eq $otherText) "another CA's defaults.json is left as it is ($r3)"

    $refused = $false
    try { [void](Get-TelimaticStepFiles 'relative/dir') } catch { $refused = $true }
    Check $refused "a 'step path' that is not absolute is refused"

    # --- a download that is not the pinned archive installs nothing
    $bad = Join-Path $tmp 'step_windows_0.31.0_amd64.zip'
    [IO.File]::WriteAllText($bad, 'not the step archive')
    $dest = Join-Path $tmp 'dest-bad'
    $msg = ''
    try { [void](Expand-TelimaticStepArchive $bad (Get-TelimaticStepAsset 'AMD64').Sha256 $dest) } catch { $msg = $_.Exception.Message }
    Check ($msg -match 'SHA-256 MISMATCH' -and -not (Test-Path $dest)) 'a download that is not the pinned archive is refused, and nothing is unpacked'

    if ($WindowsZip) {
        $dest = Join-Path $tmp 'dest-real'
        $work = Join-Path $tmp 'work-real'
        New-Item -ItemType Directory -Path $work | Out-Null
        $exe = Expand-TelimaticStepArchive $WindowsZip (Get-TelimaticStepAsset 'AMD64').Sha256 $work
        $head = [IO.File]::ReadAllBytes($exe)[0..1]
        Check ((Split-Path -Leaf $exe) -eq 'step.exe' -and $head[0] -eq 0x4D -and $head[1] -eq 0x5A) 'the real Windows amd64 archive passes its pin and unpacks step.exe (an MZ executable)'
    } else {
        Write-Host 'SKIP  the real Windows archive (no -WindowsZip given)'
    }

    # --- our own step copy is used only at the pinned version (a moved pin installs the new one)
    $fake = Join-Path $tmp 'fake-step'
    [IO.File]::WriteAllText($fake, "#!/bin/sh`necho 'Smallstep CLI/0.30.0 (fake)'`n")
    & chmod 755 $fake
    Check (-not (Test-TelimaticPinnedStep $fake)) 'a step that answers 0.30.0 is not the pinned version'
    [IO.File]::WriteAllText($fake, "#!/bin/sh`necho 'Smallstep CLI/0.31.0 (fake)'`n")
    Check (Test-TelimaticPinnedStep $fake) 'a step that answers 0.31.0 is the pinned version'

    # --- a root file that differs only in letter case is not "done" (base64 is case-sensitive)
    $files2 = Get-TelimaticStepFiles (Join-Path $tmp 'case-home')
    [void](Set-TelimaticStepConfig $files2)
    [IO.File]::WriteAllText($files2.Root, (Get-TelimaticCertPem).ToLowerInvariant())
    Check (-not (Test-TelimaticStepConfigDone $files2)) 'a root file that differs only in letter case is rewritten'

    # --- the PATH check (the registry write itself is Windows only)
    Check (Test-TelimaticPathHas 'C:\Windows;C:\Users\a\AppData\Local\Programs\step\' 'C:\Users\a\AppData\Local\Programs\step') 'a PATH entry with a trailing backslash counts'
    Check (-not (Test-TelimaticPathHas 'C:\Windows;C:\stepx' 'C:\step')) 'a PATH entry that only starts the same does not count'

    # --- the whole script, in a child pwsh with HOME in the temp directory
    $childHome = Join-Path $tmp 'child-home'
    New-Item -ItemType Directory -Path $childHome | Out-Null
    $env:HOME = $childHome
    # pwsh itself writes its own files under HOME: what a bare pwsh leaves is the baseline.
    & pwsh -NoProfile -Command '$null' | Out-Null
    $baseline = (@(Get-ChildItem -Force -Recurse $childHome | ForEach-Object FullName) | Sort-Object) -join "`n"
    $out = & pwsh -NoProfile -File $script -Show -Email 'Jane@Example.org' -User 'ext-jane' 2>&1 | Out-String
    Check ($LASTEXITCODE -eq 0 -and $out -match 'step ssh login jane@example.org --provisioner google-outside --principal ext-jane' -and $out -match 'nothing was changed') "-Show exits 0, names the sign-in, changes nothing`n$out"
    $now = (@(Get-ChildItem -Force -Recurse $childHome | ForEach-Object FullName) | Sort-Object) -join "`n"
    Check ($now -eq $baseline) "-Show writes nothing in HOME`n$now"
    if (-not (Test-TelimaticOnWindows)) {
        $out = & pwsh -NoProfile -File $script -Step -NoLogin 2>&1 | Out-String
        Check ($LASTEXITCODE -ne 0 -and $out -match 'WINDOWS settings' -and ((@(Get-ChildItem -Force -Recurse $childHome | ForEach-Object FullName) | Sort-Object) -join "`n") -eq $baseline) "off Windows, -Step stops with an error and changes nothing`n$out"
    }
    $probe = "`$User = 'mine'; `$s = [IO.File]::ReadAllText('$script'); try { `$s | Invoke-Expression } catch { }; & ([scriptblock]::Create(`$s)) -Show | Out-Null; Write-Output ('SESSION-ALIVE user=' + `$User + ' functions=' + @(Get-Command *Telimatic* -ErrorAction SilentlyContinue).Count)"
    $out = & pwsh -NoProfile -Command $probe 2>&1 | Out-String
    Check ($out -match 'SESSION-ALIVE') "the session survives both the iex form and the scriptblock form`n$out"
    Check ($out -match 'SESSION-ALIVE user=mine functions=0') "irm | iex leaves the person's session as it was (their `$User, no Telimatic functions)`n$out"

    # --- a download cut short runs nothing: cut just after the name of the last call, and just
    # before the final brace (both prefixes of the real file)
    $full = [IO.File]::ReadAllText($script)
    $at = $full.LastIndexOf('Invoke-TelimaticSetup')
    foreach ($cut in @($full.Substring(0, $at + 'Invoke-TelimaticSetup'.Length), $full.Substring(0, $full.LastIndexOf('}')))) {
        $cutFile = Join-Path $tmp 'cut.ps1'
        [IO.File]::WriteAllText($cutFile, $cut)
        $out = & pwsh -NoProfile -Command "try { [IO.File]::ReadAllText('$cutFile') | Invoke-Expression } catch { }; 'DONE'" 2>&1 | Out-String
        Check ($out -notmatch 'Telimatic internal root CA') "a download cut at byte $($cut.Length) of $($full.Length) runs nothing`n$out"
    }
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "$($script:total - $script:failed)/$($script:total) checks passed"
if ($script:failed -gt 0) { exit 1 }
