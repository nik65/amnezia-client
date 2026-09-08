[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $Iso,
    [Parameter(Mandatory = $true)] [string] $Output,
    [Parameter(Mandatory = $true)] [string] $AdminPasswordFile
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
$xml = $template.Replace("__LAB_ADMIN_PASSWORD__", [Security.SecurityElement]::Escape($password)).Replace("__SEED_NONCE__", $seedNonce)
Set-Content -LiteralPath (Join-Path $staging "Autounattend.xml") -Value $xml -Encoding UTF8 -NoNewline
$oem = Join-Path $staging '$OEM$\$1\ProgramData\AmneziaLab'
New-Item -ItemType Directory -Force -Path $oem | Out-Null
Copy-Item -LiteralPath (Join-Path $scriptDir "guest_templates\windows11\install-qga.cmd") -Destination (Join-Path $oem "install-qga.cmd")
Copy-Item -LiteralPath (Join-Path $scriptDir "guest_templates\windows11\install-qga.cmd") -Destination (Join-Path $staging "install-qga.cmd")
Set-Content -LiteralPath (Join-Path $staging "amnezia-lab-seed-$seedNonce.txt") -Value "profile=windows-x64`nseed_nonce=$seedNonce`n" -Encoding ASCII -NoNewline

$answerIso = Join-Path $resolvedOut "windows-answer.iso"
$stagingWsl = (& wsl.exe wslpath -a -u ($staging -replace '\\','/')).Trim()
$answerWsl = (& wsl.exe wslpath -a -u ($answerIso -replace '\\','/')).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($stagingWsl)) { throw "WSL wslpath is required to build answer media" }
& wsl.exe -e genisoimage -quiet -volid AMNEZIALAB -o $answerWsl $stagingWsl | Out-Null
if ($LASTEXITCODE -ne 0) { throw "WSL genisoimage failed with exit code $LASTEXITCODE" }
$isoHash = (Get-FileHash -LiteralPath $Iso -Algorithm SHA256).Hash.ToLowerInvariant()
$answerHash = (Get-FileHash -LiteralPath $answerIso -Algorithm SHA256).Hash.ToLowerInvariant()
$templateHash = (Get-FileHash -LiteralPath (Join-Path $scriptDir "guest_templates\windows11\autounattend.xml.template") -Algorithm SHA256).Hash.ToLowerInvariant()
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
    seed_nonce = $seedNonce
    seed_volume_label = "AMNEZIALAB"
    qemu_started = $false
    secure_boot = $true
    tpm = "2.0"
    nic = "e1000"
    driver_policy = "signed-only"
    candidate_credentials = "absent"
    secrets_note = "password was supplied from an external file; do not commit answer media"
}
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $resolvedOut "provisioning-manifest.json") -Encoding UTF8
Write-Output "prepared Windows answer media in $resolvedOut (installer/QEMU not started)"
