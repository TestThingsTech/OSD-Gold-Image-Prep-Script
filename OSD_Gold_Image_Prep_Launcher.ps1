<#
    OSD Gold Image Prep Launcher

    Downloads the current OSD Gold Image Prep script before every run and
    starts the downloaded copy. If the update source is unavailable, the most
    recently downloaded copy is used instead.

    Run:
      PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File .\OSD_Gold_Image_Prep_Launcher.ps1

    While the GitHub repository is private, use an OCI Object Storage
    pre-authenticated-request URL instead:
      .\OSD_Gold_Image_Prep_Launcher.ps1 -ScriptUri 'https://...'
#>

[CmdletBinding()]
param(
    # Change this to an OCI Object Storage PAR URL while the repository is private.
    [string]$ScriptUri = 'https://raw.githubusercontent.com/TestThingsTech/OSD-Gold-Image-Prep-Script/main/OSD_Gold_Image_Prep_Script.ps1',

    # Leave blank to cache beside this launcher.
    [string]$CachePath = ''
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if ([string]::IsNullOrWhiteSpace($CachePath)) {
    $launcherDirectory = if ($PSScriptRoot) {
        $PSScriptRoot
    } elseif ($PSCommandPath) {
        Split-Path -Path $PSCommandPath -Parent
    } else {
        (Get-Location).Path
    }

    $CachePath = Join-Path -Path $launcherDirectory -ChildPath 'OSD_Gold_Image_Prep_Script.ps1'
}

function Write-LauncherMessage {
    param([string]$Message, [ConsoleColor]$Color = [ConsoleColor]::Gray)
    Write-Host $Message -ForegroundColor $Color
}

function Test-DownloadedScript {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $false
    }

    if ((Get-Item -LiteralPath $Path).Length -lt 1024) {
        return $false
    }

    $firstContent = (Get-Content -LiteralPath $Path -TotalCount 5) -join "`n"
    return ($firstContent.TrimStart() -match '^(<#|#|\[CmdletBinding\(\)|param\(|\$)')
}

$cacheDirectory = Split-Path -Path $CachePath -Parent
$downloadPath = "$CachePath.download"

if (-not (Test-Path -LiteralPath $cacheDirectory -PathType Container)) {
    New-Item -Path $cacheDirectory -ItemType Directory -Force | Out-Null
}

$downloadSucceeded = $false
try {
    Write-LauncherMessage 'Checking for the latest OSD Gold Image Prep script...' Cyan
    Invoke-WebRequest -Uri $ScriptUri -OutFile $downloadPath -UseBasicParsing

    if (-not (Test-DownloadedScript -Path $downloadPath)) {
        throw 'The downloaded file does not appear to be a valid OSD Gold Image Prep script.'
    }

    Move-Item -LiteralPath $downloadPath -Destination $CachePath -Force
    $downloadSucceeded = $true
    Write-LauncherMessage 'Latest script downloaded successfully.' Green
}
catch {
    Remove-Item -LiteralPath $downloadPath -Force -ErrorAction SilentlyContinue
    Write-LauncherMessage ("Could not download the latest script: {0}" -f $_.Exception.Message) Yellow
}

if (-not (Test-DownloadedScript -Path $CachePath)) {
    Write-LauncherMessage 'No valid cached copy is available. Check the update URL and network access.' Red
    exit 1
}

if (-not $downloadSucceeded) {
    Write-LauncherMessage 'Running the previously downloaded cached copy.' Yellow
}

Write-LauncherMessage 'Starting OSD Gold Image Prep...' Cyan
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $CachePath
exit $LASTEXITCODE
