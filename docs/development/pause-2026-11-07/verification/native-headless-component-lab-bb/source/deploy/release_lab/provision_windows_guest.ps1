[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $Iso,
    [Parameter(Mandatory = $true)] [string] $Output,
    [Parameter(Mandatory = $true)] [string] $AdminPasswordFile,
    [ValidateSet('qemu','hyperv')] [string] $Transport = 'qemu',
    [string] $BootstrapId
)

$ErrorActionPreference = "Stop"
# Prepare answer media and a manifest only. Never start an installer, QEMU,
# Hyper-V, WSL, or a Windows service from this runner.
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not (Test-Path -LiteralPath $Iso -PathType Leaf)) { throw "ISO not found: $Iso" }
if (-not (Test-Path -LiteralPath $AdminPasswordFile -PathType Leaf)) { throw "password file not found: $AdminPasswordFile" }
$resolvedOut = [IO.Path]::GetFullPath($Output)
if (Test-Path -LiteralPath $resolvedOut) { throw "output exists; choose a new run directory (recursive overwrite is refused)" }
New-Item -ItemType Directory -Path $resolvedOut | Out-Null
$staging = Join-Path $resolvedOut ("answer-media-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $staging | Out-Null
$password = (Get-Content -LiteralPath $AdminPasswordFile -Raw).TrimEnd("`r", "`n")
if ([string]::IsNullOrWhiteSpace($password) -or $password.Contains("__LAB_ADMIN_PASSWORD__")) { throw "password file is empty or contains the template marker" }
if ($password.Length -lt 12) { throw "labadmin password must be at least 12 characters" }
$template = Get-Content -LiteralPath (Join-Path $scriptDir "guest_templates\windows11\autounattend.xml.template") -Raw
$seedNonce = [guid]::NewGuid().ToString("N")
$goldenBootstrapId = if ([string]::IsNullOrWhiteSpace($BootstrapId)) { "golden-$seedNonce" } else { $BootstrapId }
if ($goldenBootstrapId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$') { throw "bootstrap identifier is invalid" }
$findstrBootstrapId = $goldenBootstrapId.Replace('.', '\.')
$xml = $template.Replace("__LAB_ADMIN_PASSWORD__", [Security.SecurityElement]::Escape($password)).Replace("__SEED_NONCE__", $seedNonce)
if ($Transport -eq 'hyperv') {
    # Hyper-V uses VMbus/PowerShell Direct. The launcher is deliberately short;
    # all marker validation is performed by the seed-local helper.
    $helperName = "hyperv-seed-$seedNonce.ps1"
    $helperTemplate = Get-Content -LiteralPath (Join-Path $scriptDir "guest_templates\windows11\hyperv-seed-helper.ps1.template") -Raw
    $helperText = $helperTemplate.Replace('__SEED_NONCE__', $seedNonce).Replace('__BOOTSTRAP_ID__', $goldenBootstrapId)
    Set-Content -LiteralPath (Join-Path $staging $helperName) -Value $helperText -Encoding UTF8 -NoNewline
    $hypervFirstLogon = "<FirstLogonCommands><SynchronousCommand wcm:action=""add"" xmlns:wcm=""http://schemas.microsoft.com/WMIConfig/2002/State""><Order>1</Order><CommandLine>cmd /c ""for %D in (D E F G H I J K L M N O P Q R S T U V W X Y Z) do if exist %D:\$helperName powershell.exe -NoProfile -ExecutionPolicy Bypass -File %D:\$helperName""</CommandLine><Description>Run the uniquely named Hyper-V seed helper</Description></SynchronousCommand></FirstLogonCommands>"
    $xml = [regex]::Replace($xml, '<FirstLogonCommands>.*?</FirstLogonCommands>', $hypervFirstLogon, [Text.RegularExpressions.RegexOptions]::Singleline)
}
$commandLineMatches = [regex]::Matches($xml, '(?s)<CommandLine>(.*?)</CommandLine>')
foreach ($commandLineMatch in $commandLineMatches) {
    $decodedCommandLine = [System.Net.WebUtility]::HtmlDecode($commandLineMatch.Groups[1].Value)
    if ($decodedCommandLine.Length -gt 1024) { throw "generated FirstLogonCommands.CommandLine exceeds the Windows 1024-character limit" }
    if ($Transport -eq 'hyperv' -and $decodedCommandLine.Length -gt 256) { throw "generated Hyper-V launcher exceeds the preferred 256-character limit" }
}
Set-Content -LiteralPath (Join-Path $staging "Autounattend.xml") -Value $xml -Encoding UTF8 -NoNewline
$oem = Join-Path $staging '$OEM$\$1\ProgramData\AmneziaLab'
New-Item -ItemType Directory -Force -Path $oem | Out-Null
if ($Transport -eq 'qemu') {
    Copy-Item -LiteralPath (Join-Path $scriptDir "guest_templates\windows11\install-qga.cmd") -Destination (Join-Path $oem "install-qga.cmd")
    Copy-Item -LiteralPath (Join-Path $scriptDir "guest_templates\windows11\install-qga.cmd") -Destination (Join-Path $staging "install-qga.cmd")
}
Set-Content -LiteralPath (Join-Path $staging "amnezia-lab-seed-$seedNonce.txt") -Value "profile=windows-x64`nbackend=$Transport`nbootstrap_id=$goldenBootstrapId`nseed_nonce=$seedNonce`n" -Encoding ASCII -NoNewline

$answerIso = Join-Path $resolvedOut "windows-answer.iso"
$stagingWsl = (& wsl.exe wslpath -a -u ($staging -replace '\\','/')).Trim()
$answerWsl = (& wsl.exe wslpath -a -u ($answerIso -replace '\\','/')).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($stagingWsl)) { throw "WSL wslpath is required to build answer media" }
& wsl.exe -e genisoimage -quiet -J -R -volid AMNEZIALAB -o $answerWsl $stagingWsl | Out-Null
if ($LASTEXITCODE -ne 0) { throw "WSL genisoimage failed with exit code $LASTEXITCODE" }
$isoListing = (& wsl.exe -e isoinfo -J -f -i $answerWsl 2>&1)
if ($LASTEXITCODE -ne 0) { throw "WSL isoinfo failed to verify generated answer ISO with exit code $LASTEXITCODE" }
$isoListingText = ($isoListing -join "`n")
if ($isoListingText -notmatch '(?im)/Autounattend\.xml(?:;1)?\s*$' -or $isoListingText -notmatch "(?im)/amnezia-lab-seed-$([regex]::Escape($seedNonce))\.txt(?:;1)?\s*$") { throw "generated answer ISO file list is missing the long-name Autounattend.xml or nonce marker" }
if ($Transport -eq 'hyperv' -and $isoListingText -notmatch "(?im)/$([regex]::Escape($helperName))(?:;1)?\s*$") { throw "generated Hyper-V answer ISO file list is missing the nonce-named seed helper" }
if ($Transport -eq 'hyperv' -and $isoListingText -match '(?im)(^|/)install-qga\.cmd\s*$') { throw "Hyper-V answer ISO unexpectedly contains the QGA installer" }
$isoHash = (Get-FileHash -LiteralPath $Iso -Algorithm SHA256).Hash.ToLowerInvariant()
$answerHash = (Get-FileHash -LiteralPath $answerIso -Algorithm SHA256).Hash.ToLowerInvariant()
$templateHash = (Get-FileHash -LiteralPath (Join-Path $scriptDir "guest_templates\windows11\autounattend.xml.template") -Algorithm SHA256).Hash.ToLowerInvariant()
$helperHash = if ($Transport -eq 'hyperv') { (Get-FileHash -LiteralPath (Join-Path $staging $helperName) -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
$manifest = [ordered]@{
    schema = 1
    profile = "windows-x64"
    source_iso = [IO.Path]::GetFileName($Iso)
    source_iso_sha256 = $isoHash
    answer_iso = "windows-answer.iso"
    answer_iso_sha256 = $answerHash
    seed_sha256 = $answerHash
    template = "guest_templates/windows11/autounattend.xml.template"
    template_sha256 = $templateHash
    hyperv_helper = if ($Transport -eq 'hyperv') { $helperName } else { $null }
    hyperv_helper_sha256 = $helperHash
    seed_nonce = $seedNonce
    bootstrap_id = $goldenBootstrapId
    bootstrap_identity = "golden-os-bootstrap"
    product_run_marker = "separate-future-product-run"
    seed_volume_label = "AMNEZIALAB"
    transport = $Transport
    qemu_started = $false
    secure_boot = $true
    tpm = "2.0"
    nic = if ($Transport -eq 'hyperv') { "none" } else { "e1000" }
    driver_policy = "signed-only"
    candidate_credentials = "absent"
    secrets_note = "password was supplied from an external file; do not commit answer media"
}
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $resolvedOut "provisioning-manifest.json") -Encoding UTF8
Write-Output "prepared Windows answer media in $resolvedOut (installer/QEMU not started)"
