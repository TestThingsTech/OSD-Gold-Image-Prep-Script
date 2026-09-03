<#
Modes:
1. Prepare OSD image only (no AD or Entra ID join on deployed instances)
2. Prepare OSD image + automatic AD domain join on deployed instances
3. Prepare OSD image + automatic Entra ID join using a PPKG during specialize

If AD join is enabled, credential/config source can be:
- Instance tags
- Manual OCI Vault secret OCIDs
- Manual AD credentials

If Entra ID join is enabled, place exactly one .ppkg file in the same folder as this script before you launch it.
The script finds the .ppkg file, stages it to C:\Recovery\Customizations\<original filename>.ppkg during specialize, and removes the staged copy after a successful Entra ID install.
If no .ppkg file is found, or if more than one .ppkg file is present, the script pauses until the folder is corrected.

Run as admin:
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\temp\Script.ps1"


OCI PERMISSIONS REQUIRED IF USING SECRETS
=========================================

Use OCI Marketplace -> All Applications -> Secure Desktops
OCI Secure Desktops Resource Manager Stack for base policies

This script supports retrieving Active Directory credentials from OCI Vault
using Instance Principals and OCI.PSModules.Secrets.

Security Architecture (Best Practice)
-------------------------------------

• A centralized Vault exists in the Security compartment.
• Each workload/application compartment contains its own:
    - Encryption Keys
    - Secrets

This allows teams to manage their own secrets without requiring access to
the central security vault infrastructure.

Example layout:

Tenancy
 ├─ SecurityCompartment
 │   └─ Vault (centralized vault)
 │
 └─ DesktopCompartment
     ├─ Keys
     └─ Secrets

Policy&Grouping examples if not using "OCI Secure Desktops Resource Manager Stack" from Marketplace that creates similiar policies (general best practice)

SecureDesktopUsersGroup
<add users>

SecureDesktopAdminsGroup
<add users>

SecureDesktopsUsersGroupAccessPolicy ('domain'/'group' e.g. 'VDI'/'SecureDesktopUsersGroup', default domain no prefix)
Allow group 'SecureDesktopUsersGroup' to use published-desktop in compartment id ocid1.compartment.oc1..

SecureDesktopAdminsGroupAccessPolicy ('domain'/'group' e.g. 'VDI'/'SecureDesktopAdminsGroup', default domain no prefix)
Allow group 'SecureDesktopAdminsGroup' to manage desktop-pool-family in compartment id ocid1.compartment.oc1..
Allow group 'SecureDesktopAdminsGroup' to read all-resources in compartment id ocid1.compartment.oc1..
Allow group 'SecureDesktopAdminsGroup' to use virtual-network-family in compartment id ocid1.compartment.oc1..
Allow group 'SecureDesktopAdminsGroup' to use instance-images in compartment id ocid1.compartment.oc1..

SecureDesktopsPoolInstancesDynamicGroup
instance.compartment.id = 'ocid1.compartment.oc1..'

SecureDesktopsPoolInstancesDynamicGroupPolicy 
Allow dynamic-group Default/SecureDesktopsPoolInstancesDynamicGroup to read secret-bundles in compartment id ocid1.compartment.oc1..
Allow dynamic-group Default/SecureDesktopsPoolInstancesDynamicGroup to use keys in compartment id ocid1.compartment.oc1..
Allow dynamic-group Default/SecureDesktopsPoolInstancesDynamicGroup to use vault in compartment id ocid1.compartment.oc1.. (should be in different compartment than pool instances)

SecureDesktopsPoolsDynamicGroup
resource.type = 'desktoppool'

SecureDesktopsPoolsDynamicGroupPolicy
Allow dynamic-group Default/SecureDesktopsPoolsDynamicGroup to {DOMAIN_INSPECT} in tenancy
Allow dynamic-group Default/SecureDesktopsPoolsDynamicGroup to inspect users in tenancy
Allow dynamic-group Default/SecureDesktopsPoolsDynamicGroup to inspect compartments in tenancy
Allow dynamic-group Default/SecureDesktopsPoolsDynamicGroup to use tag-namespaces in tenancy
Allow dynamic-group Default/SecureDesktopsPoolsDynamicGroup to read instance-images in compartment id ocid1.compartment.oc1..
Allow dynamic-group Default/SecureDesktopsPoolsDynamicGroup to use virtual-network-family in compartment id ocid1.compartment.oc1..
Allow dynamic-group Default/SecureDesktopsPoolsDynamicGroup to {VCN_ATTACH, VCN_DETACH} in compartment id ocid1.compartment.oc1..
Allow dynamic-group Default/SecureDesktopsPoolsDynamicGroup to manage instance-family in compartment id ocid1.compartment.oc1..
Allow dynamic-group Default/SecureDesktopsPoolsDynamicGroup to manage volume-family in compartment id ocid1.compartment.oc1..
Allow dynamic-group Default/SecureDesktopsPoolsDynamicGroup to manage dedicated-vm-hosts in compartment id ocid1.compartment.oc1..
Allow dynamic-group Default/SecureDesktopsPoolsDynamicGroup to manage orm-family in compartment id ocid1.compartment.oc1..
Allow dynamic-group Default/SecureDesktopsPoolsDynamicGroup to {VNIC_CREATE, VNIC_DELETE} in compartment id ocid1.compartment.oc1..
Allow dynamic-group Default/SecureDesktopsPoolsDynamicGroup to manage instance-configurations in compartment id ocid1.compartment.oc1..
Allow dynamic-group Default/SecureDesktopsPoolsDynamicGroup to manage virtual-network-family in compartment id ocid1.compartment.oc1..
Allow dynamic-group Default/SecureDesktopsPoolsDynamicGroup to {NETWORK_SECURITY_GROUP_MOVE} in compartment id ocid1.compartment.oc1..

Tag-Based Domain Join Configuration
-----------------------------------

Expected freeFormTags on the instance:

osd_ib:ad_user_ocid   = <secret OCID containing AD username>
osd_ib:ad_pass_ocid   = <secret OCID containing AD password>
osd_ib:ad_fqdn        = <domain fqdn>
osd_ib:ad_ou          = <OU DN>
osd_ib:ad_dc          = <optional domain controllers>
osd_ib:ad_timezone    = <optional Windows timezone ID>


Other Requirements
------------------

• Instance must be able to access the OCI metadata service:
  http://169.254.169.254/opc/v2/instance

• Instance must have network access to Active Directory / domain controllers.

• Cloudbase-Init must be installed. (Already in OCI provided images.)

• PowerShell 7 will be installed automatically if required.

• OCI.PSModules.Secrets module will be installed automatically if required.

• Secrets must contain the raw credential value (not JSON).

#>
$currUser  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currUser)

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {

    $scriptPath = $MyInvocation.MyCommand.Path

    if ([string]::IsNullOrWhiteSpace($scriptPath)) {
        Write-Host "ERROR: Could not determine the script path for elevation." -ForegroundColor Red
        exit 99
    }

    $escapedPath = $scriptPath.Replace("'", "''")
    $cmd = "& '$escapedPath'; `$code = `$LASTEXITCODE; Write-Host ''; Write-Host 'Press Enter to close.' -ForegroundColor Yellow; Read-Host; exit `$code"

    try {
        Start-Process -FilePath "powershell.exe" `
            -Verb RunAs `
            -ArgumentList @(
                '-NoProfile',
                '-ExecutionPolicy', 'Bypass',
                '-NoExit',
                '-Command', $cmd
            ) | Out-Null

        exit 0
    }
    catch {
        Write-Host "Elevation was cancelled. Exiting." -ForegroundColor Red
        exit 98
    }
}

Write-Host "================================================================================" -ForegroundColor Yellow
Write-Host " WARNING: This operation prepares the VM for OCI Secure Desktops imaging." -ForegroundColor Yellow
Write-Host " Sysprep needs to run to prep instance." -ForegroundColor Yellow
Write-Host " OCI policy examples in script." -ForegroundColor Yellow
Write-Host " If the script seems to go idle press the left arrow key while terminal is in focus." -ForegroundColor Yellow
Write-Host "================================================================================" -ForegroundColor Yellow
Write-Host ""

$script:ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } elseif ($MyInvocation.MyCommand.Path) { Split-Path -Parent $MyInvocation.MyCommand.Path } else { (Get-Location).Path }

$tmp_dir = "C:\temp"
New-Item -ItemType Directory -Path $tmp_dir -Force | Out-Null

$Logfile = "$tmp_dir\osd_prep.log"
Remove-Item -Path $Logfile -ErrorAction SilentlyContinue | Out-Null

# Reduce noisy progress output for automation (downloads / module installs)
$global:ProgressPreference = 'SilentlyContinue'

function Logwrite {
    param([string]$logstring)
    $datentime = Get-Date -Format g
    Add-Content $Logfile -Value ("{0}: {1}" -f $datentime, $logstring)
}

$OSDRoot                 = "C:\ProgramData\OSD"
$DomainJoinPersistScript = Join-Path $OSDRoot "domainjoin_secret.ps1"

try {
    New-Item -ItemType Directory -Path $OSDRoot -Force | Out-Null
    Logwrite ("Ensured {0} exists." -f $OSDRoot)
} catch {
    Logwrite ("ERROR: Failed to create {0}: {1}" -f $OSDRoot, $_.Exception.Message)
}

# -------------------------------------------------------------------
# Common helpers
# -------------------------------------------------------------------

function Write-ErrorExit {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [string]$Cause = "",
        [string]$Fix = "",
        [string]$Details = "",
        [Parameter(Mandatory=$true)][int]$Code
    )

    Write-Host ""
    Write-Host "ERROR: $Message" -ForegroundColor Red

    if (-not [string]::IsNullOrWhiteSpace($Cause)) {
        Write-Host "Cause: $Cause" -ForegroundColor Yellow
    }

    if (-not [string]::IsNullOrWhiteSpace($Fix)) {
        Write-Host "Fix: $Fix" -ForegroundColor Yellow
    }

    if (-not [string]::IsNullOrWhiteSpace($Details)) {
        Write-Host "Details: $Details" -ForegroundColor DarkYellow
    }

    Write-Host "Exit Code: $Code" -ForegroundColor DarkGray

    Logwrite ("ERROR: {0} | Cause: {1} | Fix: {2} | Details: {3} | ExitCode: {4}" -f $Message, $Cause, $Fix, $Details, $Code)

    exit $Code
}

function Test-PowerShell7Installed {
    return (Test-Path "C:\Program Files\PowerShell\7\pwsh.exe")
}

function Test-OCISecretsModuleInstalled {
    $module = Get-Module -ListAvailable -Name OCI.PSModules.Secrets |
        Sort-Object Version -Descending |
        Select-Object -First 1

    return [bool]$module
}


function Get-EntraProvisioningPackageSourcePath {
    $scriptRoot = if ($script:ScriptRoot) {
        $script:ScriptRoot
    } elseif ($PSScriptRoot) {
        $PSScriptRoot
    } elseif ($MyInvocation.MyCommand.Path) {
        Split-Path -Parent $MyInvocation.MyCommand.Path
    } else {
        (Get-Location).Path
    }

    while ($true) {
        $ppkgFiles = Get-ChildItem -Path $scriptRoot -Filter '*.ppkg' -File -ErrorAction SilentlyContinue |
            Sort-Object Name

        if ($ppkgFiles.Count -eq 1) {
            $selected = $ppkgFiles[0]
            Write-Host ("Using '{0}' file for Entra ID enrollment." -f $selected.Name) -ForegroundColor Green
            Logwrite ("Using .ppkg file for Entra ID enrollment: {0}" -f $selected.FullName)
            return $selected.FullName
        }

        Write-Host ""
        if ($ppkgFiles.Count -eq 0) {
            Write-Host ("No .ppkg file was found in the script folder: {0}" -f $scriptRoot) -ForegroundColor Yellow
            Write-Host "Place exactly one .ppkg file in that folder before continuing." -ForegroundColor Yellow
            Write-Host "The script will pause here until one .ppkg file is present." -ForegroundColor Yellow
            Logwrite ("No .ppkg file found in script folder {0}; waiting for user to place one." -f $scriptRoot)
        }
        else {
            Write-Host ("More than one .ppkg file was found in the script folder: {0}" -f $scriptRoot) -ForegroundColor Yellow
            Write-Host "Keep only one .ppkg file in the folder before continuing." -ForegroundColor Yellow
            Write-Host "The script will pause here until only one .ppkg file remains." -ForegroundColor Yellow
            foreach ($file in $ppkgFiles) {
                Write-Host (" - {0}" -f $file.Name) -ForegroundColor Yellow
            }
            Logwrite ("Multiple .ppkg files found in script folder {0}; waiting for user to leave only one." -f $scriptRoot)
        }

        [void](Read-Host "Press Enter after fixing the .ppkg file(s) to recheck the folder")
    }
}



function Stage-EntraProvisioningPackage {
    param(
        [string]$SourcePath = (Get-EntraProvisioningPackageSourcePath),
        [string]$DestinationPath = ""
    )

    if (-not (Test-Path $SourcePath)) {
        Write-ErrorExit `
            -Message "Entra ID provisioning package not found." `
            -Cause "A .ppkg file is required for Entra ID join." `
            -Fix "Place exactly one .ppkg file in the same folder as this script before you continue." `
            -Details $SourcePath `
            -Code 30
    }

    if ([string]::IsNullOrWhiteSpace($DestinationPath)) {
        $destinationDir = 'C:\Recovery\Customizations'
        $destinationLeaf = Split-Path -Path $SourcePath -Leaf
        $DestinationPath = Join-Path $destinationDir $destinationLeaf
    }

    $destinationDir = Split-Path -Path $DestinationPath -Parent
    if (-not (Test-Path $destinationDir)) {
        New-Item -ItemType Directory -Path $destinationDir -Force | Out-Null
    }

    Copy-Item -Path $SourcePath -Destination $DestinationPath -Force
    Remove-Item -Path $SourcePath -Force -ErrorAction SilentlyContinue
    Logwrite ("Staged Entra ID provisioning package from {0} to {1} and removed source file." -f $SourcePath, $DestinationPath)

    return $DestinationPath
}


function Cleanup-ImagePrepArtifacts {

    Write-Host "Cleaning temporary image preparation files..." -ForegroundColor Cyan
    Logwrite "Cleaning temporary image preparation artifacts."

    try {
        Remove-Item "C:\temp\*" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
    } catch {}

    try {
    Get-ChildItem "C:\ProgramData\OSD" -Force -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -notin @("rdp_access.ps1", "rdp_access.xml")
		} | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
	} catch {}

    try {
        Remove-Item "C:\ProgramData\Oracle\OCI\Desktops\enable_rdp.txt" -Force -ErrorAction SilentlyContinue
    } catch {}

    try {
        Remove-Item $Logfile -Force -ErrorAction SilentlyContinue
    } catch {}
}

function Invoke-DismToFile {
    param(
        [Parameter(Mandatory=$true)][string[]]$Args,
        [Parameter(Mandatory=$true)][string]$OutFile
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "dism.exe"
    $psi.Arguments = ($Args -join " ")
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.CreateNoWindow = $true

    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    $null = $p.Start()

    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()

    $content = @()
    $content += "=== DISM COMMAND ==="
    $content += "dism.exe $($psi.Arguments)"
    $content += "=== EXIT CODE ==="
    $content += $p.ExitCode
    $content += "=== STDOUT ==="
    $content += $stdout
    if ($stderr) {
        $content += "=== STDERR ==="
        $content += $stderr
    }

    $content | Out-File -FilePath $OutFile -Encoding utf8 -Force
    return $p.ExitCode
}

function Ensure-NoPendingUpdates {
    param(
        [switch]$SkipCheck
    )

    if ($SkipCheck) {
        Write-Host "WARNING: Skipping Windows Update check at user request." -ForegroundColor Yellow
        Write-Host "WARNING: Pending Windows updates can cause Sysprep to fail or never complete." -ForegroundColor Yellow
        Logwrite "Skipped Windows Update check at user request. Sysprep may not complete if updates are pending."
        return
    }

    Write-Host "Checking for available Windows Updates..." -ForegroundColor Cyan

    try {
        $updateSession  = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $searchResult   = $updateSearcher.Search("IsInstalled=0 and Type='Software'")

        if ($searchResult.Updates.Count -eq 0) {
            Write-Host "OK: No Windows Updates available." -ForegroundColor Green
            Logwrite "No Windows Updates available."
            return
        }

        $criticalUpdates    = @()
        $nonCriticalUpdates = @()

        foreach ($update in $searchResult.Updates) {
            $title = [string]$update.Title
            $categories = @($update.Categories | ForEach-Object { $_.Name }) -join ', '

            $isCritical = $false

            if ($title -match 'Security|Critical') {
                $isCritical = $true
            }

            if ($categories -match 'Security Updates|Critical Updates|Definition Updates') {
                $isCritical = $true
            }

            $updateInfo = [PSCustomObject]@{
                Title      = $title
                Categories = $categories
            }

            if ($isCritical) {
                $criticalUpdates += $updateInfo
            } else {
                $nonCriticalUpdates += $updateInfo
            }
        }

        Write-Host ""
        Write-Host ("WARNING: {0} update(s) are available." -f $searchResult.Updates.Count) -ForegroundColor Yellow
        Logwrite ("WARNING: {0} update(s) are available." -f $searchResult.Updates.Count)

        if ($criticalUpdates.Count -gt 0) {
            Write-Host ""
            Write-Host "Critical/Security updates detected:" -ForegroundColor Red
            Logwrite ("Critical/Security updates detected: {0}" -f $criticalUpdates.Count)

            foreach ($u in $criticalUpdates) {
                Write-Host ("  [CRITICAL] {0}" -f $u.Title) -ForegroundColor Red
                if ($u.Categories) {
                    Write-Host ("             Categories: {0}" -f $u.Categories) -ForegroundColor DarkRed
                }
                Logwrite ("CRITICAL UPDATE: {0} | Categories: {1}" -f $u.Title, $u.Categories)
            }

            if ($nonCriticalUpdates.Count -gt 0) {
                Write-Host ""
                Write-Host "Other available updates:" -ForegroundColor Yellow
                foreach ($u in $nonCriticalUpdates) {
                    Write-Host ("  [INFO] {0}" -f $u.Title) -ForegroundColor Yellow
                    if ($u.Categories) {
                        Write-Host ("         Categories: {0}" -f $u.Categories) -ForegroundColor DarkYellow
                    }
                    Logwrite ("NON-CRITICAL UPDATE: {0} | Categories: {1}" -f $u.Title, $u.Categories)
                }
            }

            Write-ErrorExit `
                -Message "Critical or security-related Windows Updates are pending." `
                -Cause "System is not fully patched for imaging." `
                -Fix "Install all critical/security updates and reboot until they are no longer offered." `
                -Code 1
        }

        Write-Host ""
        Write-Host "No critical/security updates were detected, but updates are still available:" -ForegroundColor Yellow
        foreach ($u in $nonCriticalUpdates) {
            Write-Host ("  [INFO] {0}" -f $u.Title) -ForegroundColor Yellow
            if ($u.Categories) {
                Write-Host ("         Categories: {0}" -f $u.Categories) -ForegroundColor DarkYellow
            }
            Logwrite ("NON-CRITICAL UPDATE: {0} | Categories: {1}" -f $u.Title, $u.Categories)
        }

        Write-Host ""
        do {
            $continueChoice = (Read-Host "Continue anyway? Enter Y to continue or N to stop").Trim().ToUpper()
        } until ($continueChoice -in @('Y','N'))

        if ($continueChoice -eq 'N') {
            Write-ErrorExit `
                -Message "User chose not to continue with pending non-critical updates." `
                -Cause "Updates are available and user aborted imaging." `
                -Fix "Install updates and reboot, or rerun the script and choose to continue." `
                -Code 1
        }

        Write-Host "Continuing with pending non-critical updates by user choice." -ForegroundColor Yellow
        Logwrite "User chose to continue with pending non-critical updates."
    }
    catch {
        Write-Host "WARNING: Could not query Windows Update COM API. Continuing, but imaging may be risky." -ForegroundColor Yellow
        Write-Host "Details: $($_.Exception.Message)" -ForegroundColor Yellow
        Logwrite ("WARNING: Windows Update COM API query failed: {0}" -f $_.Exception.Message)
    }
}

function Ensure-NoPendingReboot {
    Write-Host "Checking for pending reboot / servicing state..." -ForegroundColor Cyan
    $pending = $false

    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
        $pending = $true
        Write-Host "Pending: CBS RebootPending" -ForegroundColor Yellow
    }
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
        $pending = $true
        Write-Host "Pending: WindowsUpdate RebootRequired" -ForegroundColor Yellow
    }
    try {
        $pfr = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
        if ($null -ne $pfr.PendingFileRenameOperations) {
            $pending = $true
            Write-Host "Pending: PendingFileRenameOperations" -ForegroundColor Yellow
        }
    } catch {}

    if ($pending) {
        Write-ErrorExit `
			-Message "System requires a reboot before imaging." `
			-Cause "Pending servicing or reboot flag detected." `
			-Fix "Reboot the system and rerun the script." `
			-Code 1
    } else {
        Write-Host "OK: No pending reboot / servicing operations detected." -ForegroundColor Green
        Logwrite "No pending reboot or servicing operations detected."
    }
}

function Invoke-OptionalDismCleanup {
    $dismCleanup = Read-Host "Do you want to run DISM component cleanup? (Y/N)"
    if ($dismCleanup -notmatch '^[Yy]$') {
        Write-Host "Skipping DISM component cleanup." -ForegroundColor Yellow
        Logwrite "Skipped DISM component cleanup."
        return
    }

    $analyzeLog = Join-Path $tmp_dir "dism_analyze_component_store.log"
    $cleanupLog = Join-Path $tmp_dir "dism_startcomponentcleanup.log"

    Write-Host "Analyzing component store (non-interactive)..." -ForegroundColor Cyan
    $rc = Invoke-DismToFile -Args @("/Online","/Cleanup-Image","/AnalyzeComponentStore","/English") -OutFile $analyzeLog

    if ($rc -ne 0) {
        Write-Host "WARNING: DISM analyze failed (exit $rc). Skipping cleanup. See: $analyzeLog" -ForegroundColor Yellow
        Logwrite ("WARNING: DISM analyze failed with exit code {0}" -f $rc)
        return
    }

    $analyzeText = Get-Content $analyzeLog -Raw -ErrorAction SilentlyContinue
    $cleanupRecommended = $false
    if ($analyzeText -match "Component Store Cleanup Recommended\s*:\s*Yes") {
        $cleanupRecommended = $true
    }

    if (-not $cleanupRecommended) {
        Write-Host "OK: DISM reports cleanup is NOT recommended. Skipping StartComponentCleanup." -ForegroundColor Green
        Write-Host "Analyze log: $analyzeLog" -ForegroundColor DarkGray
        Logwrite "DISM AnalyzeComponentStore reports cleanup not recommended."
        return
    }

    Write-Host "Cleanup recommended. Running StartComponentCleanup (non-interactive)..." -ForegroundColor Cyan
    $rc2 = Invoke-DismToFile -Args @("/Online","/Cleanup-Image","/StartComponentCleanup","/English") -OutFile $cleanupLog
    if ($rc2 -eq 0) {
        Write-Host "OK: DISM StartComponentCleanup complete." -ForegroundColor Green
        Write-Host "Cleanup log: $cleanupLog" -ForegroundColor DarkGray
        Logwrite "DISM StartComponentCleanup completed successfully."
    } else {
        Write-Host "WARNING: DISM cleanup returned exit $rc2. See: $cleanupLog" -ForegroundColor Yellow
        Logwrite ("WARNING: DISM StartComponentCleanup returned exit code {0}" -f $rc2)
    }
}

function Invoke-OptionalAppxRemoval {

    Write-Host "Removing AppX packages for all users..." -ForegroundColor Cyan
    Logwrite "Removing AppX packages for all users."

    $oldEap = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"

    Get-AppxPackage -AllUsers | ForEach-Object {
        try { Remove-AppxPackage -Package $_.PackageFullName } catch {}
    }

    Get-AppxProvisionedPackage -Online | ForEach-Object {
        try { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName | Out-Null } catch {}
    }

    $ErrorActionPreference = $oldEap
}

function Ensure-EnableRdpScript {
    Write-Host "Ensuring Cloudbase-Init enable_rdp.ps1 exists..." -ForegroundColor Cyan
    Logwrite "Ensuring enable_rdp.ps1 exists."

    $localScriptsPath = "C:\Program Files\Cloudbase Solutions\Cloudbase-Init\LocalScripts"
    $enableRdpScript  = "$localScriptsPath\enable_rdp.ps1"

    New-Item -ItemType Directory -Path "C:\ProgramData\Oracle\OCI\Desktops" -Force | Out-Null

    $enableRdpContent = @'
#ps1_sysnative
$script_path=$Env:ProgramData+"\Oracle\OCI\Desktops"
$log="$script_path\enable_rdp.txt"
Start-Transcript -Path $log -Append
Write-Host "Enabling rdp port" | Out-Default
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -name fDenyTSConnections | Out-Default
date | Out-Default
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -name fDenyTSConnections -Value 0 | Out-Default
Enable-NetFirewallRule -Name RemoteDesktop-Shadow-In-TCP | Out-Default
Enable-NetFirewallRule -Name RemoteDesktop-UserMode-In-TCP | Out-Default
Enable-NetFirewallRule -Name RemoteDesktop-UserMode-In-UDP | Out-Default
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -name fDenyTSConnections | Out-Default
'@

    if (-not (Test-Path $enableRdpScript)) {
        Write-Host "enable_rdp.ps1 not found. Creating it..." -ForegroundColor Cyan
        if (-not (Test-Path $localScriptsPath)) {
            New-Item -ItemType Directory -Path $localScriptsPath -Force | Out-Null
        }
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($enableRdpScript, $enableRdpContent, $utf8NoBom)
    } else {
        Write-Host "enable_rdp.ps1 already exists." -ForegroundColor Yellow
    }
}

function Setup-FirstUserRdpRestriction {
    Write-Host "Configuring temporary RDP bootstrap access..." -ForegroundColor Cyan
    Logwrite "Configuring temporary RDP bootstrap access."

    $rdpAccessScript = "C:\ProgramData\OSD\rdp_access.ps1"
    $rdpAccessXml    = "C:\ProgramData\OSD\rdp_access.xml"

    $scriptTxt = @'
$task = "OSDRDPAccess"

try {
    $sessionLine = quser 2>$null | Select-String "rdp-tcp"
    if (-not $sessionLine) { exit 0 }

    $line = $sessionLine.Line

    if ($line -match "^\s*>?\s*([^\s]+)\s+") {
        $rdpUser = $matches[1]
    }

    if (-not $rdpUser) { exit 0 }

    Remove-LocalGroupMember -SID "S-1-5-32-555" -Member "S-1-5-11" -ErrorAction SilentlyContinue
    Add-LocalGroupMember -SID "S-1-5-32-555" -Member $rdpUser -ErrorAction SilentlyContinue

    if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $task -Confirm:$false
    }

    Remove-Item "C:\ProgramData\OSD\rdp_access.xml" -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\ProgramData\OSD\rdp_access.ps1" -Force -ErrorAction SilentlyContinue
}
catch {
}
'@

    $xmlTxt = @'
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>System</Author>
    <URI>\OSDRDPAccess</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Command>
      <Arguments>-ExecutionPolicy Bypass -File C:\ProgramData\OSD\rdp_access.ps1</Arguments>
    </Exec>
  </Actions>
</Task>
'@

    try {
        Set-Content -Path $rdpAccessScript -Value $scriptTxt -Encoding UTF8 -ErrorAction Stop
        Set-Content -Path $rdpAccessXml -Value $xmlTxt -Encoding Unicode -ErrorAction Stop

        Remove-LocalGroupMember -SID "S-1-5-32-555" -Member "S-1-5-11" -ErrorAction SilentlyContinue
        Add-LocalGroupMember -SID "S-1-5-32-555" -Member "S-1-5-11" -ErrorAction Stop

        $taskResult = & schtasks.exe /Create /TN "OSDRDPAccess" /XML $rdpAccessXml /F 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "schtasks.exe failed: $($taskResult -join ' ')"
        }

        Write-Host "OK: Temporary RDP bootstrap task created." -ForegroundColor Green
        Logwrite "Temporary Authenticated Users RDP access granted and OSDRDPAccess task created."
    }
    catch {
        Write-ErrorExit `
            -Message "Failed configuring temporary RDP bootstrap access." `
            -Cause "Could not create the OSDRDPAccess scheduled task or modify RDP group membership." `
            -Fix "Run from a fully elevated Administrator session and verify Task Scheduler service is healthy." `
            -Details $_.Exception.Message `
            -Code 61
    }
}

function Set-DefaultUserVisualFx {
    Write-Host "Setting VisualFXSetting=2 in Default User profile..." -ForegroundColor Cyan
    Logwrite "Setting Default User VisualFXSetting=2."

    $defaultNtUser = "C:\Users\Default\NTUSER.DAT"
    $hiveWasLoadedByThisFunction = $false

    try {
        if (-not (Test-Path $defaultNtUser)) {
            Write-Host "WARNING: Default profile hive not found at $defaultNtUser. Skipping." -ForegroundColor Yellow
            Logwrite "WARNING: Default NTUSER.DAT not found."
            return
        }

        if (-not (Test-Path "Registry::HKEY_USERS\DefUser")) {
            & reg.exe load "HKU\DefUser" "$defaultNtUser" | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to load Default User hive from $defaultNtUser"
            }
            $hiveWasLoadedByThisFunction = $true
        }

        $explorerPath = "Registry::HKEY_USERS\DefUser\Software\Microsoft\Windows\CurrentVersion\Explorer"
        $defPath      = "$explorerPath\VisualEffects"

        if (-not (Test-Path $explorerPath)) {
            New-Item -Path $explorerPath -Force | Out-Null
        }

        if (-not (Test-Path $defPath)) {
            New-Item -Path $defPath -Force | Out-Null
        }

        New-ItemProperty -Path $defPath -Name "VisualFXSetting" -PropertyType DWord -Value 2 -Force | Out-Null

        Write-Host "OK: Default User VisualFXSetting set to 2." -ForegroundColor Green
        Logwrite "OK: Default User VisualFXSetting set to 2."
    }
    catch {
        Write-Host "WARNING: Failed to set Default User VisualFXSetting. Skipping." -ForegroundColor Yellow
        Write-Host "Details: $($_.Exception.Message)" -ForegroundColor Yellow
        Logwrite ("WARNING: Failed to set Default User VisualFXSetting: {0}" -f $_.Exception.Message)
    }
    finally {
        if ($hiveWasLoadedByThisFunction) {
            try {
                & reg.exe unload "HKU\DefUser" | Out-Null
            } catch {}
        }
    }
}

function Remove-OldVfxLogonTrigger {
    Write-Host "Removing VFX logon script trigger (Run key)..." -ForegroundColor Cyan
    Logwrite "Removing old VFX logon trigger."
    try {
        Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "!VFX" -ErrorAction SilentlyContinue
        Remove-Item "C:\ProgramData\Oracle\OCI\Desktops\VFX.ps1" -Force -ErrorAction SilentlyContinue
        Remove-Item "C:\ProgramData\Oracle\OCI\Desktops\VFX.log" -Force -ErrorAction SilentlyContinue
    } catch {}
}

function Remove-CurrentLocalUserBestEffort {
    $currentUser = $Env:USERNAME

    if ($currentUser -ieq "Administrator") {
        Write-Host "Skipping removal of built-in Administrator account." -ForegroundColor Yellow
        Logwrite "Skipped removal of built-in Administrator account."
        return
    }

    Write-Host "Removing local user '$currentUser'..." -ForegroundColor Cyan
    Logwrite ("Attempting to remove local user {0}" -f $currentUser)

    try {
        Remove-LocalGroupMember -Group "Remote Desktop Users" -Member $currentUser -ErrorAction SilentlyContinue
        Logwrite ("Removed {0} from Remote Desktop Users." -f $currentUser)
    } catch {}

    try {
        Remove-LocalUser -Name $currentUser -ErrorAction Stop
        Logwrite ("Successfully removed local user {0}" -f $currentUser)
    } catch {
        Write-Host "User removal skipped or failed (possibly profile in use)." -ForegroundColor Yellow
        Logwrite ("WARNING: Failed to remove local user {0}: {1}" -f $currentUser, $_.Exception.Message)
    }
}

function read_tags {
    $endpoint = "http://169.254.169.254/opc/v2/instance"
    $headers = @{ "Authorization" = "Bearer Oracle" }

    try {
        $meta_data = Invoke-RestMethod -Uri $endpoint -Headers $headers
        return $meta_data.freeFormTags
    } catch {
        Write-ErrorExit `
			-Message "No freeFormTags found on the instance." `
			-Cause "Metadata service returned no tags." `
			-Fix "Ensure required AD tags are defined on the instance." `
			-Code 22
    }
}

function input_timezone {
    $curr_tz = Get-TimeZone
    $curr_tz_id = $curr_tz.Id

    Write-Host "Current system timezone is $curr_tz_id" -ForegroundColor Cyan

    do {
        $yes_no = (Read-Host "Do you use $curr_tz_id as the VM timezone? (y/n)").Trim().ToLower()
    } while ($yes_no -notin @('y','n'))

    if ($yes_no -eq 'y') {
        return $curr_tz_id
    }

    while ($true) {
        $input_tz = (Read-Host 'Enter timezone ID (e.g. Pacific Standard Time)').Trim()

        if ([string]::IsNullOrWhiteSpace($input_tz)) {
            Write-Host 'Timezone ID cannot be blank.' -ForegroundColor Red
            continue
        }

        $tz = Get-TimeZone -ListAvailable | Where-Object { $_.Id -eq $input_tz } | Select-Object -First 1

        if ($tz) {
            return $tz.Id
        }

        Write-Host 'Invalid timezone ID.' -ForegroundColor Red

        do {
            $yes_no = (Read-Host 'Do you want to view the timezone ID list? (y/n)').Trim().ToLower()
        } while ($yes_no -notin @('y','n'))

        if ($yes_no -eq 'y') {
            try {
                Get-TimeZone -ListAvailable |
                    Sort-Object Id |
                    ForEach-Object { "{0,-35} [{1}]" -f $_.Id, $_.DisplayName } |
                    Out-Host -Paging
            } catch [System.Management.Automation.HaltCommandException] {
                # User stopped paging
                Out-Null
            }
        }
    }
}

function Test-OUDNFormat {
    param([string]$dn)
    if ([string]::IsNullOrWhiteSpace($dn)) { return $false }
    $dn = $dn.Trim()
    if ($dn -notmatch '^OU=.+,DC=.+') { return $false }
    if ($dn -match '[;\"<>]') { return $false }
    return $true
}

function Test-ADOrganizationalUnit {
    param(
        [Parameter(Mandatory=$true)][string]$DomainFQDN,
        [Parameter(Mandatory=$true)][string]$Username,
        [Parameter(Mandatory=$true)][string]$Password,
        [Parameter(Mandatory=$true)][string]$OUDN,
        [string]$DomainController = ""
    )

    Write-Host ""
    Write-Host "Validating OU existence in Active Directory..." -ForegroundColor Cyan
    Logwrite ("Validating OU DN: {0}" -f $OUDN)

    try {
        $target = if ($DomainController) { $DomainController } else { $DomainFQDN }
        $ldapPath = "LDAP://$target/$OUDN"

        $entry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath, $Username, $Password)

        # FORCE bind
        $native = $entry.NativeObject

        # Force property load (this is key)
        $entry.RefreshCache()

        $schema = $entry.SchemaClassName

        # HARD FAIL CONDITIONS
        if ([string]::IsNullOrWhiteSpace($schema)) {
            throw "LDAP bind succeeded but object type is empty (invalid DN or lookup failure)."
        }

        if ($schema -ne "organizationalUnit") {
            throw "Object exists but is NOT an OU (type: $schema)"
        }

        Write-Host "OK: OU exists and is valid." -ForegroundColor Green
        Write-Host ("Validated OU against: {0}" -f $target) -ForegroundColor DarkGray
        Logwrite ("OK: OU validation succeeded against {0}" -f $target)

        return $true
    }
    catch {
        $errorMsg = $_.Exception.Message

        Write-ErrorExit `
            -Message "OU validation failed." `
            -Cause "Invalid OU DN or lookup issue." `
            -Fix "Verify OU path EXACTLY matches AD structure and domain components." `
            -Details ("Target: {0} | OU: {1} | {2}" -f $target, $OUDN, $errorMsg) `
            -Code 51
    }
}

function Test-ADUsernameFormat {
    param(
        [Parameter(Mandatory=$true)][string]$Username
    )

    if ([string]::IsNullOrWhiteSpace($Username)) {
        return $false
    }

    # UPN format (user@domain.com)
    if ($Username -match '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
        return $true
    }

    # DOMAIN\user format
    if ($Username -match '^[^\\\s]+\\[^\\\s]+$') {
        return $true
    }

    # Simple username (allowed but warn)
    if ($Username -match '^[^\s]+$') {
        Write-Host "WARNING: Username does not include domain (recommended: user@domain.com or DOMAIN\user)" -ForegroundColor Yellow
        return $true
    }

    return $false
}

function Invoke-Pwsh7SecretCommand {
    param(
        [Parameter(Mandatory=$true)][string]$SecretOCID,
        [Parameter(Mandatory=$true)][string]$Mode
    )

    $pwshPath = "C:\Program Files\PowerShell\7\pwsh.exe"

    if (-not (Test-Path $pwshPath)) {
        Write-ErrorExit `
            -Message "PowerShell 7 not found." `
            -Cause "pwsh.exe is required for OCI secret operations." `
            -Fix "Ensure-PowerShell7Latest must complete successfully before secret validation." `
            -Details $pwshPath `
            -Code 26
    }

    $tempScript = Join-Path $tmp_dir ("pwsh_secret_check_{0}.ps1" -f ([guid]::NewGuid().ToString("N")))
    $tempOut    = Join-Path $tmp_dir ("pwsh_secret_out_{0}.json" -f ([guid]::NewGuid().ToString("N")))

    $scriptContent = @'
param(
    [string]$SecretOCID,
    [string]$Mode,
    [string]$OutFile
)

$ErrorActionPreference = "Stop"

try {
    Import-Module OCI.PSModules.Secrets -ErrorAction Stop

    $secretVersion = Get-OCISecretsSecretBundle -SecretId $SecretOCID -AuthType InstancePrincipal -ErrorAction Stop

    if (-not $secretVersion) {
        throw "Secret bundle response was empty."
    }

    if (-not $secretVersion.SecretBundleContent) {
        throw "Secret bundle content was not returned."
    }

    $base64Secret = $secretVersion.SecretBundleContent.Content

    if ([string]::IsNullOrWhiteSpace($base64Secret)) {
        throw "Secret content is empty."
    }

    $decodedSecret = [System.Text.Encoding]::UTF8.GetString(
        [System.Convert]::FromBase64String($base64Secret)
    ).Trim()

    if ([string]::IsNullOrWhiteSpace($decodedSecret)) {
        throw "Decoded secret value is empty."
    }

    $result = [pscustomobject]@{
        success = $true
        value   = $decodedSecret
        error   = ""
        mode    = $Mode
    }

    $result | ConvertTo-Json -Compress | Set-Content -Path $OutFile -Encoding UTF8
    exit 0
}
catch {
    $result = [pscustomobject]@{
        success = $false
        value   = ""
        error   = $_.Exception.Message
        mode    = $Mode
    }

    $result | ConvertTo-Json -Compress | Set-Content -Path $OutFile -Encoding UTF8
    exit 1
}
'@

    try {
        Set-Content -Path $tempScript -Value $scriptContent -Encoding UTF8

        & $pwshPath -NoLogo -NoProfile -ExecutionPolicy Bypass -File $tempScript -SecretOCID $SecretOCID -Mode $Mode -OutFile $tempOut | Out-Null

        if (-not (Test-Path $tempOut)) {
            throw "pwsh 7 did not produce an output file."
        }

        $result = Get-Content -Path $tempOut -Raw | ConvertFrom-Json
        return $result
    }
    finally {
        Remove-Item -Path $tempScript -Force -ErrorAction SilentlyContinue | Out-Null
        Remove-Item -Path $tempOut -Force -ErrorAction SilentlyContinue | Out-Null
    }
}
# -------------------------------------------------------------------
# Domain join helpers
# -------------------------------------------------------------------

function Ensure-PowerShell7Latest {
    param(
        [string]$TempDir = "C:\temp"
    )

    $pwshPath = "C:\Program Files\PowerShell\7\pwsh.exe"

    function Get-InstalledPwshVersion {
        if (-not (Test-Path $pwshPath)) {
            return $null
        }

        try {
            $v = & $pwshPath -NoLogo -NoProfile -Command '$PSVersionTable.PSVersion.ToString()'
            return [version]$v
        }
        catch {
            Logwrite ("WARNING: Failed to read installed PowerShell version from {0}: {1}" -f $pwshPath, $_.Exception.Message)
            return $null
        }
    }

    function Get-LatestPwshMsiInfo {
        $headers = @{
            "User-Agent" = "OSD-GoldImageBuilder"
            "Accept"     = "application/vnd.github+json"
        }

        try {
            Write-Host "Checking latest PowerShell release..." -ForegroundColor Cyan
            Logwrite "Checking latest PowerShell release from GitHub."

            $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/PowerShell/PowerShell/releases/latest" -Headers $headers -Method Get

            if (-not $rel) {
                Write-ErrorExit `
                    -Message "Failed to query latest PowerShell release." `
                    -Cause "GitHub API returned an empty response." `
                    -Fix "Check internet access, proxy settings, or GitHub availability." `
                    -Code 30
            }

            $tag = $rel.tag_name
            $ver = $tag.TrimStart("v")

            $msiAsset = $rel.assets | Where-Object {
                $_.name -match "^PowerShell-$([regex]::Escape($ver))-win-x64\.msi$"
            } | Select-Object -First 1

            if (-not $msiAsset) {
                $msiAsset = $rel.assets | Where-Object {
                    $_.name -like "PowerShell-*-win-x64.msi"
                } | Select-Object -First 1
            }

            if (-not $msiAsset) {
                Write-ErrorExit `
                    -Message "Failed to locate a PowerShell MSI asset." `
                    -Cause ("No win-x64 MSI asset was found in release {0}." -f $tag) `
                    -Fix "Verify the GitHub release contents or retry later." `
                    -Code 31
            }

            return [pscustomobject]@{
                TagName = $tag
                Version = [version]$ver
                MsiName = $msiAsset.name
                MsiUrl  = $msiAsset.browser_download_url
            }
        }
        catch {
            Write-ErrorExit `
                -Message "Failed to determine the latest PowerShell version." `
                -Cause "GitHub release lookup failed." `
                -Fix "Check internet access, TLS/proxy settings, or GitHub availability." `
                -Details $_.Exception.Message `
                -Code 32
        }
    }

    try {
        New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
    }
    catch {
        Write-ErrorExit `
            -Message "Failed to prepare temporary directory." `
            -Cause "The script could not create the working temp path." `
            -Fix "Verify permissions and disk availability." `
            -Details ("TempDir: {0} | {1}" -f $TempDir, $_.Exception.Message) `
            -Code 33
    }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $latest = Get-LatestPwshMsiInfo
    $installed = Get-InstalledPwshVersion

    if ($installed -and $installed -ge $latest.Version) {
        Write-Host ("OK: PowerShell 7 already installed ({0}) >= latest ({1}). No action needed." -f $installed, $latest.Version) -ForegroundColor Green
        Logwrite ("PowerShell 7 already installed ({0}) >= latest ({1}); no action." -f $installed, $latest.Version)
        return
    }

    if ($installed) {
        Write-Host ("Upgrading PowerShell 7 from {0} to {1} ({2})..." -f $installed, $latest.Version, $latest.TagName) -ForegroundColor Cyan
        Logwrite ("PowerShell 7 installed version is {0}; upgrading to {1} ({2})." -f $installed, $latest.Version, $latest.TagName)
    }
    else {
        Write-Host ("PowerShell 7 not found. Installing latest {0} ({1})..." -f $latest.Version, $latest.TagName) -ForegroundColor Cyan
        Logwrite ("PowerShell 7 not found; installing latest {0} ({1})." -f $latest.Version, $latest.TagName)
    }

    $msiPath = Join-Path $TempDir $latest.MsiName

    $downloaded = $false
    for ($i = 1; $i -le 3; $i++) {
        try {
            Write-Host ("Downloading PowerShell MSI (attempt {0} of 3)..." -f $i) -ForegroundColor Cyan
            Logwrite ("Downloading PowerShell MSI (attempt {0}): {1}" -f $i, $latest.MsiUrl)

            Invoke-WebRequest -Uri $latest.MsiUrl -OutFile $msiPath -UseBasicParsing

            Write-Host "PowerShell MSI download complete." -ForegroundColor Green
            Logwrite "PowerShell MSI download complete."

            $downloaded = $true
            break
        }
        catch {
            Write-Host ("WARNING: Download attempt {0} failed." -f $i) -ForegroundColor Yellow
            Write-Host ("Details: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
            Logwrite ("Download attempt {0} failed: {1}" -f $i, $_.Exception.Message)

            if ($i -lt 3) {
                Write-Host "Retrying in 3 seconds..." -ForegroundColor Yellow
                Start-Sleep -Seconds 3
            }
        }
    }

    if (-not $downloaded -or -not (Test-Path $msiPath)) {
        Write-ErrorExit `
            -Message "PowerShell 7 download failed." `
            -Cause "MSI could not be downloaded after multiple attempts." `
            -Fix "Check internet access, proxy settings, or GitHub availability." `
            -Details ("Expected MSI path: {0}" -f $msiPath) `
            -Code 27
    }

    $args = "/i `"$msiPath`" /qn /norestart ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=0 ENABLE_PSREMOTING=0"

    Write-Host ("Installing PowerShell 7 from {0}..." -f $msiPath) -ForegroundColor Cyan
    Logwrite ("Installing PowerShell from {0}" -f $msiPath)

    $p = Start-Process "msiexec.exe" -ArgumentList $args -Wait -PassThru -NoNewWindow

    if ($p.ExitCode -ne 0) {
        Write-ErrorExit `
            -Message "PowerShell 7 installation failed." `
            -Cause ("msiexec returned a non-zero exit code: {0}" -f $p.ExitCode) `
            -Fix "Review the MSI, confirm it downloaded correctly, and verify Windows Installer is healthy." `
            -Details ("MSI path: {0}" -f $msiPath) `
            -Code 28
    }

    Write-Host "PowerShell 7 installation completed. Verifying..." -ForegroundColor Cyan
    Logwrite "PowerShell 7 installation completed. Verifying pwsh.exe."

    $installedAfter = Get-InstalledPwshVersion
    if (-not $installedAfter) {
        Write-ErrorExit `
            -Message "PowerShell 7 install verification failed." `
            -Cause "pwsh.exe was not found after the installer completed." `
            -Fix "Verify the MSI installed successfully and confirm pwsh.exe exists under C:\Program Files\PowerShell\7." `
            -Details ("Expected path: {0}" -f $pwshPath) `
            -Code 29
    }

    Write-Host ("OK: PowerShell 7 installed successfully: {0}" -f $installedAfter) -ForegroundColor Green
    Logwrite ("PowerShell 7 installed successfully: {0}" -f $installedAfter)
}

function Test-ADDomainReachability {
    param(
        [Parameter(Mandatory=$true)][string]$DomainFQDN,
        [string]$DomainControllerList = ""
    )

    Write-Host ""
    Write-Host "Validating Active Directory DNS and network reachability..." -ForegroundColor Cyan
    Logwrite ("Validating AD DNS/network reachability for domain: {0}" -f $DomainFQDN)

    if ([string]::IsNullOrWhiteSpace($DomainFQDN)) {
        Write-ErrorExit `
            -Message "Domain FQDN is blank." `
            -Cause "No domain name was provided." `
            -Fix "Enter a valid domain FQDN such as example.com." `
            -Code 40
    }

    try {
        Resolve-DnsName -Name $DomainFQDN -ErrorAction Stop | Out-Null
        Write-Host "OK: Domain DNS resolved: $DomainFQDN" -ForegroundColor Green
        Logwrite ("OK: Domain DNS resolved: {0}" -f $DomainFQDN)
    }
    catch {
        Write-ErrorExit `
            -Message "Could not resolve domain FQDN: $DomainFQDN" `
            -Cause "The domain name could not be resolved in DNS." `
            -Fix "Check the domain name and verify the instance is using the correct DNS servers." `
            -Details $_.Exception.Message `
            -Code 41
    }

    $targets = @()

    if (-not [string]::IsNullOrWhiteSpace($DomainControllerList)) {
        $targets = $DomainControllerList.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    }

    if (-not $targets -or $targets.Count -eq 0) {
        try {
            $srvRecords = Resolve-DnsName -Name ("_ldap._tcp.dc._msdcs." + $DomainFQDN) -Type SRV -ErrorAction Stop
            $targets = $srvRecords | Select-Object -ExpandProperty NameTarget -Unique | ForEach-Object { $_.TrimEnd('.') }
        }
        catch {
            Write-ErrorExit `
                -Message "Could not discover domain controllers via DNS SRV records." `
                -Cause "AD-integrated DNS SRV records could not be resolved." `
                -Fix "Check AD DNS health or provide DC FQDN(s) manually." `
                -Details $_.Exception.Message `
                -Code 42
        }
    }

    if (-not $targets -or $targets.Count -eq 0) {
        Write-ErrorExit `
            -Message "No domain controllers were found to test." `
            -Cause "No explicit DCs were provided and SRV discovery returned nothing." `
            -Fix "Provide domain controller FQDN(s) manually or fix AD DNS SRV records." `
            -Code 43
    }

    $portsToTest = @(53,88,389,445)
    $reachableDcFound = $false

    foreach ($dc in $targets) {
        Write-Host ""
        Write-Host ("Testing domain controller: {0}" -f $dc) -ForegroundColor Cyan
        Logwrite ("Testing domain controller: {0}" -f $dc)

        try {
            Resolve-DnsName -Name $dc -ErrorAction Stop | Out-Null
            Write-Host "OK: DC DNS resolved: $dc" -ForegroundColor Green
            Logwrite ("OK: DC DNS resolved: {0}" -f $dc)
        }
        catch {
            Write-Host "WARNING: Could not resolve DC: $dc" -ForegroundColor Yellow
            Logwrite ("WARNING: Could not resolve DC {0}: {1}" -f $dc, $_.Exception.Message)
            continue
        }

        $dcHealthy = $true

        foreach ($port in $portsToTest) {
            $test = Test-NetConnection -ComputerName $dc -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue

            if ($test) {
                Write-Host ("OK: {0} reachable on port {1}" -f $dc, $port) -ForegroundColor Green
                Logwrite ("OK: {0} reachable on port {1}" -f $dc, $port)
            }
            else {
                Write-Host ("WARNING: {0} not reachable on port {1}" -f $dc, $port) -ForegroundColor Yellow
                Logwrite ("WARNING: {0} not reachable on port {1}" -f $dc, $port)
                $dcHealthy = $false
            }
        }

        if ($dcHealthy) {
            $reachableDcFound = $true
        }
    }

    if (-not $reachableDcFound) {
        Write-ErrorExit `
            -Message "No reachable domain controller passed validation." `
            -Cause "DNS, routing, firewall, or AD service availability prevented successful connectivity checks." `
            -Fix "Verify NSGs/security lists, firewalls, routing, DC health, and required ports 53, 88, 389, and 445." `
            -Code 44
    }

    Write-Host ""
    Write-Host "OK: Active Directory DNS and reachability validation passed." -ForegroundColor Green
    Logwrite "OK: Active Directory DNS and reachability validation passed."
}

function Ensure-OCISecretsModule {
    param(
        [string]$TempDir = "C:\temp"
    )

    $pwshPath = "C:\Program Files\PowerShell\7\pwsh.exe"

    if (-not (Test-Path $pwshPath)) {
        throw "PowerShell 7 not found at $pwshPath"
    }

    Logwrite "Ensuring OCI.PSModules.Secrets is installed for AllUsers in PowerShell 7."

    New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
    $installScriptPath = Join-Path $TempDir "install_oci_secrets_module.ps1"

    $installScript = @'
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if ($PSVersionTable.PSEdition -ne 'Core') {
    throw "This installer must run under PowerShell 7+ (Core)."
}

if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
}

try {
    $repo = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
    if (-not $repo) {
        Register-PSRepository -Default -ErrorAction Stop
        $repo = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
    }
    if ($repo -and $repo.InstallationPolicy -ne "Trusted") {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
    }
} catch {
    throw ("PSGallery configuration failed: {0}" -f $_.Exception.Message)
}

$existing = Get-Module -ListAvailable -Name OCI.PSModules.Secrets | Sort-Object Version -Descending | Select-Object -First 1
if (-not $existing) {
    Install-Module -Name OCI.PSModules.Secrets -Scope AllUsers -Force -AllowClobber -ErrorAction Stop
}

$verify = Get-Module -ListAvailable -Name OCI.PSModules.Secrets | Sort-Object Version -Descending | Select-Object -First 1
if (-not $verify) {
    throw "OCI.PSModules.Secrets was not found after installation."
}

Import-Module OCI.PSModules.Secrets -Force -ErrorAction Stop
'@

    Set-Content -Path $installScriptPath -Value $installScript -Encoding UTF8

    try {
        & $pwshPath -NoLogo -NoProfile -ExecutionPolicy Bypass -File $installScriptPath 2>&1 | ForEach-Object {
            Logwrite ("OCISecretsModule: {0}" -f $_.ToString())
        }

        if ($LASTEXITCODE -ne 0) {
            throw ("OCI.PSModules.Secrets installation/validation failed with exit code {0}." -f $LASTEXITCODE)
        }

        $verifyPath = & $pwshPath -NoLogo -NoProfile -Command "(Get-Module -ListAvailable OCI.PSModules.Secrets | Sort-Object Version -Descending | Select-Object -First 1).Path"
        if (-not $verifyPath) {
            throw "OCI.PSModules.Secrets verification failed."
        }

        Logwrite ("OCI.PSModules.Secrets installed and validated successfully: {0}" -f $verifyPath)
    }
    finally {
        Remove-Item -Path $installScriptPath -Force -ErrorAction SilentlyContinue | Out-Null
    }
}

function Test-OCISecretAccess {
    param(
        [Parameter(Mandatory=$true)][string]$SecretOCID,
        [Parameter(Mandatory=$true)][string]$SecretPurpose,
        [switch]$ValidateAsADUsername
    )

    if ([string]::IsNullOrWhiteSpace($SecretOCID)) {
        Write-ErrorExit `
            -Message "$SecretPurpose secret OCID is blank." `
            -Cause "A required secret OCID was not provided." `
            -Fix "Enter a valid secret OCID or correct the instance tags." `
            -Code 20
    }

    try {
        Logwrite ("Validating instance-principal access to {0} secret through pwsh 7: {1}" -f $SecretPurpose, $SecretOCID)

        $result = Invoke-Pwsh7SecretCommand -SecretOCID $SecretOCID -Mode "validate"

        if (-not $result.success) {
            throw $result.error
        }

        $decodedSecret = [string]$result.value

        if ($ValidateAsADUsername) {
            if (-not (Test-ADUsernameFormat -Username $decodedSecret)) {
                throw "Secret value is accessible, but the AD username format is invalid. Use user@domain.com or DOMAIN\user."
            }

            if ($decodedSecret -match '^[^\\]+\\[^\\]+$') {
                Write-Host "INFO: DOMAIN\user format detected in $SecretPurpose secret. UPN (user@domain.com) is recommended." -ForegroundColor Yellow
                Logwrite ("INFO: DOMAIN\user format detected in {0} secret." -f $SecretPurpose)
            }
        }

        Write-Host "OK: Secret access validation passed for $SecretPurpose." -ForegroundColor Green
        Logwrite ("Validated access to {0} secret successfully." -f $SecretPurpose)
        return $true
    }
    catch {
        $errorMsg = $_.Exception.Message
        $cause = "Unexpected error accessing secret."
        $fix = "Check secret OCID, dynamic group membership, IAM policies, vault/key access, and secret contents."

        if ($errorMsg -match "NotAuthorized|Authorization|Forbidden") {
            $cause = "Instance does not have permission to read this secret."
            $fix = "Check dynamic group membership and IAM policy for secret-bundles, keys, and vault access."
        }
        elseif ($errorMsg -match "NotFound|404") {
            $cause = "Secret OCID is invalid, secret does not exist, or access is denied."
            $fix = "Verify the OCID is correct and confirm the instance has permission to read it."
        }
        elseif ($errorMsg -match "empty") {
            $cause = "Secret exists but contains no usable value."
            $fix = "Update the OCI Vault secret content with the raw credential value."
        }
        elseif ($errorMsg -match "username format") {
            $cause = "Secret contains an invalid AD username format."
            $fix = "Store the username as user@domain.com or DOMAIN\user."
        }
        elseif ($errorMsg -match "Import-Module|OCI\.PSModules\.Secrets") {
            $cause = "The OCI secrets module could not be loaded in PowerShell 7."
            $fix = "Re-run Ensure-OCISecretsModule and verify pwsh 7 module installation."
        }

        Write-ErrorExit `
            -Message "Secret validation failed for $SecretPurpose." `
            -Cause $cause `
            -Fix $fix `
            -Details ("Secret OCID: {0} | {1}" -f $SecretOCID, $errorMsg) `
            -Code 21
    }
}
function Get-ValidatedOCISecretValue {
    param(
        [Parameter(Mandatory=$true)][string]$SecretOCID,
        [Parameter(Mandatory=$true)][string]$SecretPurpose
    )

    try {
        Logwrite ("Retrieving {0} secret value through pwsh 7 for validation." -f $SecretPurpose)

        $result = Invoke-Pwsh7SecretCommand -SecretOCID $SecretOCID -Mode "getvalue"

        if (-not $result.success) {
            throw $result.error
        }

        $decodedSecret = [string]$result.value

        if ([string]::IsNullOrWhiteSpace($decodedSecret)) {
            throw "Decoded secret value is empty."
        }

        return $decodedSecret
    }
    catch {
        Write-ErrorExit `
            -Message "Failed retrieving $SecretPurpose secret value for validation." `
            -Cause "The secret could not be read in PowerShell 7 for credential validation." `
            -Fix "Verify the secret exists, the instance can access it, and the secret contains a raw value." `
            -Details ("Secret OCID: {0} | {1}" -f $SecretOCID, $_.Exception.Message) `
            -Code 24
    }
}
function Test-ADCredential {
    param(
        [Parameter(Mandatory=$true)][string]$DomainFQDN,
        [Parameter(Mandatory=$true)][string]$Username,
        [Parameter(Mandatory=$true)][string]$Password,
        [string]$DomainController = ""
    )

    Write-Host ""
    Write-Host "Validating AD credentials (LDAP bind only, no domain join)..." -ForegroundColor Cyan
    Logwrite ("Validating AD credentials for user {0}" -f $Username)

    try {
        $target = if (-not [string]::IsNullOrWhiteSpace($DomainController)) { $DomainController } else { $DomainFQDN }
        $ldapPath = "LDAP://$target"

        $entry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath, $Username, $Password)
        $null = $entry.NativeObject

		Write-Host "OK: AD credential validation succeeded." -ForegroundColor Green
		Write-Host ("Validated against: {0}" -f $target) -ForegroundColor DarkGray
		Logwrite ("OK: AD credential validation succeeded against {0}" -f $target)
		return $true
    }
    catch {
        $errorMsg = $_.Exception.Message
        $cause = "LDAP authentication failed."
        $fix = "Verify the username, password, DC reachability, and domain authentication path."

        if ($errorMsg -match "Logon failure|unknown user|bad password|The user name or password is incorrect") {
            $cause = "Invalid username or password."
            $fix = "Verify the credentials and try UPN format such as user@domain.com."
        }
        elseif ($errorMsg -match "server is not operational|cannot contact|The RPC server is unavailable") {
            $cause = "Domain controller is not reachable for authentication."
            $fix = "Check network connectivity, DNS, and firewall access to the domain controller."
        }

        Write-ErrorExit `
            -Message "AD credential validation failed." `
            -Cause $cause `
            -Fix $fix `
            -Details ("Target: {0} | User: {1} | {2}" -f $target, $Username, $errorMsg) `
            -Code 50
    }
}
function domainjoin_file_create {
    param(
		[ValidateSet("tags","vault","manual")]
		[string]$JoinMode,
		$freeFormTags,
		[string]$VaultUserSecretOCID = "",
		[string]$VaultPassSecretOCID = "",
		[string]$DomainFQDN = "",
		[string]$DomainControllerList = ""
	)

    Remove-Item -Path $DomainJoinPersistScript -ErrorAction SilentlyContinue | Out-Null
    Logwrite ("Creating {0}." -f $DomainJoinPersistScript)

    $UseOCISecrets = $false

    $domainjoin_input1 = @'
$UseOCISecrets = __USE_OCI_SECRETS__
$Logfile = "C:\ProgramData\OSD\DomainJoin-v1.log"

function Logwrite {
    Param([string]$logstring)
    $datentime = Get-Date -Format g
    Add-Content $Logfile -Value ("{0}: {1}" -f $datentime, $logstring)
}

$script:OCISecretsAvailable = $false

if (-not (Get-Command -ErrorAction SilentlyContinue Add-Computer)) {
    Import-Module Microsoft.PowerShell.Management -UseWindowsPowerShell
}

if ($UseOCISecrets) {
    try {
        Import-Module OCI.PSModules.Secrets -ErrorAction Stop
        $script:OCISecretsAvailable = $true
        Logwrite "OCI.PSModules.Secrets imported successfully."
    } catch {
        $script:OCISecretsAvailable = $false
        Logwrite ("OCI.PSModules.Secrets import failed: {0}" -f $_.Exception.Message)
    }
} else {
    Logwrite "OCI Vault secrets not selected."
}

function Get-PlainSecret {
    param([string]$secretOCID)
    try {
        $secretVersion = Get-OCISecretsSecretBundle -SecretId $secretOCID -AuthType InstancePrincipal
        $base64Secret = $secretVersion.SecretBundleContent.Content
        return [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($base64Secret)).Trim()
    } catch {
        Logwrite ("Get-PlainSecret failed for {0}: {1}" -f $secretOCID, $_.Exception.Message)
        return $null
    }
}

function Enable-RDP {
    try {
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -Force
        Enable-NetFirewallRule -Name RemoteDesktop-Shadow-In-TCP -ErrorAction SilentlyContinue | Out-Null
        Enable-NetFirewallRule -Name RemoteDesktop-UserMode-In-TCP -ErrorAction SilentlyContinue | Out-Null
        Enable-NetFirewallRule -Name RemoteDesktop-UserMode-In-UDP -ErrorAction SilentlyContinue | Out-Null
        Logwrite "RDP enabled successfully."
    } catch {
        Logwrite ("WARNING: Failed to enable RDP: {0}" -f $_.Exception.Message)
    }
}

function Register-SelfDeleteTask {
    param(
        [Parameter(Mandatory=$true)][string]$FilePath
    )

    try {
        $taskName = "OSD-DomainJoinPersistCleanup"
        $cleanupScript = "C:\ProgramData\OSD\cleanup_persist.ps1"

        $cleanupContent = @"
`$target = "$FilePath"
Start-Sleep -Seconds 20
try {
    if (Test-Path `$target) {
        Remove-Item `$target -Force -ErrorAction SilentlyContinue
    }
} catch {}

try {
    Remove-Item "C:\ProgramData\OSD\cleanup_persist.ps1" -Force -ErrorAction SilentlyContinue
} catch {}

try {
    Unregister-ScheduledTask -TaskName "$taskName" -Confirm:`$false -ErrorAction SilentlyContinue
} catch {}
"@

        Set-Content -Path $cleanupScript -Value $cleanupContent -Encoding UTF8

        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$cleanupScript`""
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
        Logwrite ("Registered fallback self-delete task for {0}" -f $FilePath)
    } catch {
        Logwrite ("WARNING: Failed to register self-delete task: {0}" -f $_.Exception.Message)
    }
}

try {
    $partOfDomain = (Get-CimInstance Win32_ComputerSystem).PartOfDomain
} catch {
    $partOfDomain = $false
    Logwrite ("Failed to query domain membership: {0}" -f $_.Exception.Message)
}

if ($partOfDomain) {
    Enable-RDP
    Logwrite "Machine is already domain joined. Nothing to do."
    exit 0
}
'@
    Set-Content -Path $DomainJoinPersistScript -Value $domainjoin_input1 -Encoding UTF8

    switch ($JoinMode) {
        "tags" {
			$UseOCISecrets = $true

			if (-not ($freeFormTags.'osd_ib:ad_user_ocid' -and
					  $freeFormTags.'osd_ib:ad_pass_ocid' -and
					  $freeFormTags.'osd_ib:ad_fqdn' -and
					  $freeFormTags.'osd_ib:ad_ou')) {
				Write-ErrorExit `
					-Message "Required AD tags missing for tags mode." `
					-Cause "One or more required freeFormTags are not present." `
					-Fix "Add osd_ib:ad_user_ocid, osd_ib:ad_pass_ocid, osd_ib:ad_fqdn, osd_ib:ad_ou." `
					-Code 23
			}

			$userSecretOCID = $freeFormTags.'osd_ib:ad_user_ocid'
			$passSecretOCID = $freeFormTags.'osd_ib:ad_pass_ocid'
			$domname = $freeFormTags.'osd_ib:ad_fqdn'
			$DC_str = $freeFormTags.'osd_ib:ad_dc'
			$ou_dn = ($freeFormTags.'osd_ib:ad_ou').Trim()

			if (-not (Test-OUDNFormat $ou_dn)) {
				Write-ErrorExit `
					-Message "Invalid OU DN format from tags." `
					-Cause "OU DN does not match expected format." `
					-Fix "Use format: OU=VDI,DC=example,DC=com" `
					-Details $ou_dn `
					-Code 25
			}

			Test-ADOrganizationalUnit `
				-DomainFQDN $domname `
				-Username $tagUserValue `
				-Password $tagPassValue `
				-OUDN $ou_dn `
				-DomainController $firstTagDC

			# ONLY WRITE AFTER VALIDATION PASSES
			Add-Content -Path $DomainJoinPersistScript -Value "`$UserOCID = `"$userSecretOCID`"" -Encoding UTF8
			Add-Content -Path $DomainJoinPersistScript -Value "`$PassOCID = `"$passSecretOCID`"" -Encoding UTF8
			Add-Content -Path $DomainJoinPersistScript -Value "`$DomainName = `"$domname`"" -Encoding UTF8
			Add-Content -Path $DomainJoinPersistScript -Value "`$DomainNameList = `"$DC_str`"" -Encoding UTF8

			$ou_dn_escaped = $ou_dn.Replace("'", "''")
			Add-Content -Path $DomainJoinPersistScript -Value "`$ComOUfolder = `'$ou_dn_escaped`'" -Encoding UTF8

			$tagTz = ($freeFormTags.'osd_ib:ad_timezone' | ForEach-Object { "$_".Trim() })
			if (-not [string]::IsNullOrWhiteSpace($tagTz)) {
				$isValid = Get-TimeZone -ListAvailable | Where-Object { $_.Id -eq $tagTz } | Select-Object -First 1
				$script:ad_timezone = if ($isValid) { $tagTz } else { input_timezone }
			}
			else {
				$script:ad_timezone = input_timezone
			}
		}

        "vault" {
			$UseOCISecrets = $true

			$userSecretOCID = $VaultUserSecretOCID.Trim()
			$passwdSecretOCID = $VaultPassSecretOCID.Trim()

			$domname = $DomainFQDN
			$DC_str = $DomainControllerList

			while ($true) {
				$ou_dn = (Read-Host -Prompt "Computer OU DN (e.g. OU=VDI,DC=example,DC=com)").Trim()
				if (Test-OUDNFormat $ou_dn) { break }
				Write-Host "Invalid OU DN format. Example: OU=VDI,DC=example,DC=com" -ForegroundColor Red
			}

			Test-ADOrganizationalUnit `
				-DomainFQDN $DomainFQDN `
				-Username $vaultUserValue `
				-Password $vaultPassValue `
				-OUDN $ou_dn `
				-DomainController $firstVaultDC

			# ONLY WRITE AFTER VALIDATION PASSES
			Add-Content -Path $DomainJoinPersistScript -Value "`$UserOCID = `"$userSecretOCID`"" -Encoding UTF8
			Add-Content -Path $DomainJoinPersistScript -Value "`$PassOCID = `"$passwdSecretOCID`"" -Encoding UTF8
			Add-Content -Path $DomainJoinPersistScript -Value "`$DomainName = `"$domname`"" -Encoding UTF8
			Add-Content -Path $DomainJoinPersistScript -Value "`$DomainNameList = `"$DC_str`"" -Encoding UTF8

			$ou_dn_escaped = $ou_dn.Replace("'", "''")
			Add-Content -Path $DomainJoinPersistScript -Value "`$ComOUfolder = `'$ou_dn_escaped`'" -Encoding UTF8

			$script:ad_timezone = input_timezone
		}

        "manual" {
			$domname = $DomainFQDN

			$valid = $false
			do {
				$user = (Read-Host -Prompt "Enter domain username (recommended: user@domain.com; also supports DOMAIN\user)").Trim()

				if (-not (Test-ADUsernameFormat -Username $user)) {
					Write-Host "ERROR: Invalid AD username format. Use user@domain.com or DOMAIN\user." -ForegroundColor Red
					$valid = $false
				}
				else {
					if ($user -match '^[^\\]+\\[^\\]+$') {
						Write-Host "INFO: DOMAIN\user format detected. UPN (user@domain.com) is recommended." -ForegroundColor Yellow
					}

					$valid = $true
				}

			} while (-not $valid)

			$securePassword = Read-Host -Prompt "AD join password" -AsSecureString
			$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
			try {
				$password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
			}
			finally {
				if ($BSTR -ne [IntPtr]::Zero) {
					[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
				}
			}

			$firstManualDC = ""
			if (-not [string]::IsNullOrWhiteSpace($DomainControllerList)) {
				$firstManualDC = ($DomainControllerList.Split(",")[0]).Trim()
			}

			Test-ADCredential -DomainFQDN $DomainFQDN -Username $user -Password $password -DomainController $firstManualDC

			# --- OU input ---
			while ($true) {
				$ou_dn = (Read-Host -Prompt "Computer OU DN (e.g. OU=VDI,DC=example,DC=com)").Trim()
				if (Test-OUDNFormat $ou_dn) { break }
				Write-Host "Invalid OU DN format. Example: OU=VDI,DC=example,DC=com" -ForegroundColor Red
			}

			Test-ADOrganizationalUnit `
				-DomainFQDN $DomainFQDN `
				-Username $user `
				-Password $password `
				-OUDN $ou_dn `
				-DomainController $firstManualDC

			Add-Content -Path $DomainJoinPersistScript -Value "`$DomainName = `"$domname`"" -Encoding UTF8
			Add-Content -Path $DomainJoinPersistScript -Value "`$ADuser = `"$user`"" -Encoding UTF8

			$pwdEscaped = $password -replace "'", "''"
			Add-Content -Path $DomainJoinPersistScript -Value "`$ADpassword = '$pwdEscaped'" -Encoding UTF8

			# clear password AFTER all validation
			$password = $null

			$DC_str = $DomainControllerList
			Add-Content -Path $DomainJoinPersistScript -Value "`$DomainNameList = `"$DC_str`"" -Encoding UTF8

			$ou_dn_escaped = $ou_dn.Replace("'", "''")
			Add-Content -Path $DomainJoinPersistScript -Value "`$ComOUfolder = `'$ou_dn_escaped`'" -Encoding UTF8

			$script:ad_timezone = input_timezone
		}
    }

    $tz = if ($script:ad_timezone) { $script:ad_timezone } else { "UTC" }
    Add-Content -Path $DomainJoinPersistScript -Value "`$TimezoneId = `"$tz`"" -Encoding UTF8

    $domainjoin_input2 = @'
$ResolvedUserSecretOCID = $null
$ResolvedPassSecretOCID = $null

if (Get-Variable -Name UserOCID -ErrorAction SilentlyContinue) { $ResolvedUserSecretOCID = $UserOCID }
if (Get-Variable -Name PassOCID -ErrorAction SilentlyContinue) { $ResolvedPassSecretOCID = $PassOCID }

$user   = $null
$passwd = $null

if ($script:OCISecretsAvailable) {
    if ($ResolvedUserSecretOCID) { $user   = Get-PlainSecret $ResolvedUserSecretOCID }
    if ($ResolvedPassSecretOCID) { $passwd = Get-PlainSecret $ResolvedPassSecretOCID }
}

if (-not $user)   { $user = $ADuser }
if (-not $passwd) { $passwd = $ADpassword }

Logwrite ("Set timezone to {0}" -f $TimezoneId)
Set-TimeZone -Id $TimezoneId

try {
    $svc = Get-Service -Name W32Time -ErrorAction Stop
    if ($svc.StartType -eq 'Disabled') {
        Set-Service -Name W32Time -StartupType Manual
    }
    if ($svc.Status -ne 'Running') {
        Start-Service -Name W32Time -ErrorAction Stop
    }
    w32tm /resync /force | Out-Null
} catch {
    Logwrite ("WARNING: Time resync failed: {0}" -f $_.Exception.Message)
}

if ([string]::IsNullOrWhiteSpace($user) -or [string]::IsNullOrWhiteSpace($passwd)) {
    Logwrite "Domain join credentials are not available."
    exit 2
}

$PWord = ConvertTo-SecureString -String $passwd -AsPlainText -Force
$cred  = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user, $PWord
$ComputerOU = "$ComOUfolder"

$name = $env:COMPUTERNAME
Logwrite ("Final computer name for domain join: {0}" -f $name)
Logwrite ("Joining the computer to OU {0}" -f $ComputerOU)

$joined = $false
for ($i = 1; $i -le 3; $i++) {
    try {
        Add-Computer -DomainName $DomainName -OUPath $ComputerOU -Credential $cred -ErrorAction Stop
        $joined = $true
        break
    } catch {
        Logwrite ("Add-Computer attempt {0} failed: {1}" -f $i, $_.Exception.Message)
        Start-Sleep -Seconds 5
    }
}

if ($joined) {
    Enable-RDP
    Register-SelfDeleteTask -FilePath $PSCommandPath
    Logwrite ("Registered cleanup fallback for {0}" -f $PSCommandPath)
    Logwrite "Domain join succeeded."
    exit 0
} else {
    Logwrite "Domain join failed."
    exit 2
}
'@
    Add-Content -Path $DomainJoinPersistScript -Value $domainjoin_input2 -Encoding UTF8

    $boolLiteral = if ($UseOCISecrets) { '$true' } else { '$false' }

    $rawPersist = Get-Content -Path $DomainJoinPersistScript -Raw
    $rawPersist = $rawPersist.Replace('__USE_OCI_SECRETS__', $boolLiteral)
    Set-Content -Path $DomainJoinPersistScript -Value $rawPersist -Encoding UTF8

    try {
        $null = [scriptblock]::Create((Get-Content -Path $DomainJoinPersistScript -Raw))
        Logwrite ("Syntax validation passed for {0}" -f $DomainJoinPersistScript)
    } catch {
        Logwrite ("ERROR: Syntax validation failed for {0}: {1}" -f $DomainJoinPersistScript, $_.Exception.Message)
        throw
    }
}

function script_file_create {
    $scriptfile = "$tmp_dir\script.ps1"
    Remove-Item -Path $scriptfile -ErrorAction SilentlyContinue | Out-Null
    Logwrite ("Creating {0} (cloudbase-init wrapper)" -f $scriptfile)

    $script_input = @"
#ps1_sysnative

`$persist = "$DomainJoinPersistScript"
`$osdRoot = "$OSDRoot"
`$thisScript = "C:\Program Files\Cloudbase Solutions\Cloudbase-Init\LocalScripts\script.ps1"
`$enableRdpScript = "C:\Program Files\Cloudbase Solutions\Cloudbase-Init\LocalScripts\enable_rdp.ps1"
`$enableRdpLog = "C:\ProgramData\Oracle\OCI\Desktops\enable_rdp.txt"
`$wrapperLog = "C:\ProgramData\OSD\wrapper_cleanup.log"

function Write-WrapperLog {
    param([string]`$Message)
    try {
        `$dt = Get-Date -Format g
        Add-Content -Path `$wrapperLog -Value ("{0}: {1}" -f `$dt, `$Message)
    } catch {}
}

Write-WrapperLog "Wrapper started."
Write-WrapperLog "Persist path: `$persist"

if (-not (Test-Path `$persist)) {
    Write-WrapperLog "Persist script does not exist. Exiting 0."
    exit 0
}

`$pwsh = "C:\Program Files\PowerShell\7\pwsh.exe"
if (-not (Test-Path `$pwsh)) {
    Write-WrapperLog "PowerShell 7 not found. Exiting 12."
    exit 12
}

Write-WrapperLog "Launching persisted domain join script."
& `$pwsh -NoProfile -ExecutionPolicy Bypass -File `$persist
`$rc = `$LASTEXITCODE
Write-WrapperLog "Persisted script exit code: `$rc"

if (`$rc -eq 0) {

    Start-Sleep -Seconds 2
    Write-WrapperLog "Starting cleanup after successful domain join."

    # First, explicitly remove the persisted domain join script
    for (`$i = 1; `$i -le 10; `$i++) {
        try {
            if (Test-Path `$persist) {
                Write-WrapperLog "Attempt `$i removing persist script: `$persist"
                Remove-Item `$persist -Force -ErrorAction Stop
            } else {
                Write-WrapperLog "Persist script already absent before attempt `$i."
            }
            break
        } catch {
            Write-WrapperLog ("Attempt `$i failed removing persist script: {0}" -f `$_.Exception.Message)
            Start-Sleep -Seconds 2
        }
    }

    Write-WrapperLog "Persist exists after targeted cleanup: $(Test-Path `$persist)"

    # Then remove the rest of OSD artifacts except the RDP bootstrap files
    try {
        Remove-Item "C:\temp\*" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
        Write-WrapperLog "Removed C:\temp contents."
    } catch {
        Write-WrapperLog ("Failed cleaning C:\temp: {0}" -f `$_.Exception.Message)
    }

    try {
        Get-ChildItem "`$osdRoot" -Force -ErrorAction SilentlyContinue | Where-Object {
            `$_.Name -notin @("rdp_access.ps1", "rdp_access.xml", "wrapper_cleanup.log")
        } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Write-WrapperLog "Removed remaining OSD artifacts."
    } catch {
        Write-WrapperLog ("Failed cleaning OSD root: {0}" -f `$_.Exception.Message)
    }

    try {
        Remove-Item "`$thisScript" -Force -ErrorAction SilentlyContinue | Out-Null
        Write-WrapperLog "Removed LocalScripts\script.ps1"
    } catch {
        Write-WrapperLog ("Failed removing wrapper script: {0}" -f `$_.Exception.Message)
    }

    try {
        Remove-Item "`$enableRdpScript" -Force -ErrorAction SilentlyContinue | Out-Null
        Write-WrapperLog "Removed enable_rdp.ps1"
    } catch {
        Write-WrapperLog ("Failed removing enable_rdp.ps1: {0}" -f `$_.Exception.Message)
    }

    try {
        Remove-Item "`$enableRdpLog" -Force -ErrorAction SilentlyContinue | Out-Null
        Write-WrapperLog "Removed enable_rdp.txt"
    } catch {
        Write-WrapperLog ("Failed removing enable_rdp.txt: {0}" -f `$_.Exception.Message)
    }

    Write-WrapperLog "Final persist exists check before reboot: $(Test-Path `$persist)"
    Write-WrapperLog "Rebooting after successful domain join cleanup."
    shutdown.exe /r /t 5 /f
    exit 1001
}

Write-WrapperLog "Persisted script returned non-zero rc. Leaving files in place for troubleshooting."
exit 0
"@

    Set-Content -Path $scriptfile -Value $script_input -Encoding UTF8
}

function files_check {
    Logwrite ("Checking required files under {0} and ProgramData." -f $tmp_dir)

    $file1 = $DomainJoinPersistScript
    $file2 = "$tmp_dir\script.ps1"

    if (-not (Test-Path $file1)) {
        Write-Host ""
        Write-ErrorExit `
			-Message "Required file missing: $file1" `
			-Cause "Script generation failed or file was removed." `
			-Fix "Check earlier script errors and rerun." `
			-Code 10
    }
    if (-not (Test-Path $file2)) {
        Write-Host ""
        Write-Host "The file $file2 doesn't exist." -ForegroundColor Red
        Logwrite ("The file {0} doesn't exist." -f $file2)
        exit 10
    }

    Write-Host ""
    Write-Host "File check PASS." -ForegroundColor Green
    Logwrite "File check PASS."
}

function cloudbaseinit_copy_wrapper {
    $LocalScripts = "C:\Program Files\Cloudbase Solutions\Cloudbase-Init\LocalScripts"
    $destScript   = Join-Path $LocalScripts "script.ps1"

    Logwrite "Copying script.ps1 to cloudbase init LocalScripts directory"

    $cloudbaseInstalled = (
        (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
            Where-Object { $_.DisplayName -Match "^Cloudbase-Init .*" }
        ).DisplayName
    ).Count

    if ($cloudbaseInstalled -ne 1) {
        Write-ErrorExit `
            -Message "Cloudbase-Init not detected." `
            -Cause "Required component for OCI Secure Desktop is missing." `
            -Fix "Install Cloudbase-Init or use a supported OCI image." `
            -Code 11
    }

    if (-not (Test-Path $LocalScripts)) {
        New-Item -ItemType Directory -Path $LocalScripts -Force | Out-Null
    }

    try {
        Copy-Item "$tmp_dir\script.ps1" -Destination $destScript -Force -ErrorAction Stop
    }
    catch {
        Write-ErrorExit `
            -Message "Failed to copy wrapper into Cloudbase-Init LocalScripts." `
            -Cause "The startup wrapper could not be staged for first boot." `
            -Fix "Check path permissions and Cloudbase-Init installation." `
            -Details $_.Exception.Message `
            -Code 12
    }

    if (-not (Test-Path $destScript)) {
        Write-ErrorExit `
            -Message "Wrapper script is missing after copy." `
            -Cause "The Cloudbase-Init startup wrapper was not present at the destination." `
            -Fix "Verify the LocalScripts path and rerun the preparation." `
            -Details $destScript `
            -Code 13
    }

    Write-Host "OK: Cloudbase-Init wrapper copied successfully." -ForegroundColor Green
    Logwrite ("OK: Wrapper copied to {0}" -f $destScript)
}

# -------------------------------------------------------------------
# Unattend / sysprep
# -------------------------------------------------------------------

function Write-UnattendXml {
    param(
        [string]$TimeZone = "UTC",
        [string]$EntraPpkgPath = "",
        [string]$EntraPpkgSourcePath = ""
    )

    $unattend = "C:\Program Files\Cloudbase Solutions\Cloudbase-Init\conf\unattend.xml"
    $unattendDir = Split-Path -Path $unattend -Parent

    $entraPpkgCommand = ""
    if (-not [string]::IsNullOrWhiteSpace($EntraPpkgPath)) {
        # Escape single quotes for the generated helper script
        $entraPpkgPathLiteral = $EntraPpkgPath.Replace("'", "''")
        $helperScriptLiteral = (Join-Path $unattendDir "Install-EntraPpkg.ps1").Replace("'", "''")
        $unattendLiteral = $unattend.Replace("'", "''")

        # Write a short helper script so the unattend Path stays well under the limit
        $helperScript = Join-Path $unattendDir "Install-EntraPpkg.ps1"
        $helperScriptContent = @'
param()
Start-Sleep -Seconds 10
$pkg = '__PKG__'
$helperScriptPath = '__HELPER__'
$unattendPath = '__UNATTEND__'
try {
    Install-ProvisioningPackage -PackagePath $pkg -ForceInstall -QuietInstall
} finally {
    Remove-Item -Path $pkg -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $helperScriptPath -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $unattendPath -Force -ErrorAction SilentlyContinue
}
'@
        $helperScriptContent = $helperScriptContent.Replace('__PKG__', $entraPpkgPathLiteral).Replace('__HELPER__', $helperScriptLiteral).Replace('__UNATTEND__', $unattendLiteral)

        New-Item -ItemType Directory -Path $unattendDir -Force | Out-Null
        Set-Content -Path $helperScript -Value $helperScriptContent -Encoding UTF8

        $helperScriptForXml = [System.Security.SecurityElement]::Escape($helperScript)

        $entraPpkgCommand = @"
        <RunSynchronousCommand wcm:action="add">
          <Order>4</Order>
          <Path>powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$helperScriptForXml"</Path>
          <Description>Install Entra ID PPKG</Description>
          <WillReboot>Never</WillReboot>
        </RunSynchronousCommand>
"@
    }

    $unattendXml = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="generalize">
    <component name="Microsoft-Windows-PnpSysprep"
               processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35"
               language="neutral"
               versionScope="nonSxS"
               xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
               xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <PersistAllDeviceInstalls>true</PersistAllDeviceInstalls>
    </component>
  </settings>

  <settings pass="specialize">
    <component name="Microsoft-Windows-Deployment"
               processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35"
               language="neutral"
               versionScope="nonSxS"
               xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
               xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <RunSynchronous>

        <RunSynchronousCommand wcm:action="add">
          <Order>1</Order>
          <Path>cmd.exe /c reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f</Path>
          <Description>Force RDP disabled early registry</Description>
          <WillReboot>Never</WillReboot>
        </RunSynchronousCommand>

        <RunSynchronousCommand wcm:action="add">
          <Order>2</Order>
          <Path>powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Disable-NetFirewallRule -Name 'RemoteDesktop-Shadow-In-TCP','RemoteDesktop-UserMode-In-TCP','RemoteDesktop-UserMode-In-UDP' -ErrorAction SilentlyContinue"</Path>
          <Description>Force RDP disabled early firewall</Description>
          <WillReboot>Never</WillReboot>
        </RunSynchronousCommand>

        <RunSynchronousCommand wcm:action="add">
          <Order>3</Order>
          <Path>cmd.exe /c ""C:\Program Files\Cloudbase Solutions\Cloudbase-Init\Python\Scripts\cloudbase-init.exe" --config-file "C:\Program Files\Cloudbase Solutions\Cloudbase-Init\conf\cloudbase-init-unattend.conf""</Path>
          <Description>Run Cloudbase Init</Description>
          <WillReboot>OnRequest</WillReboot>
        </RunSynchronousCommand>

$entraPpkgCommand
      </RunSynchronous>
    </component>
  </settings>

  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup"
               processorArchitecture="amd64"
               publicKeyToken="31bf3856ad364e35"
               language="neutral"
               versionScope="nonSxS"
               xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
               xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <ProtectYourPC>1</ProtectYourPC>
        <SkipMachineOOBE>true</SkipMachineOOBE>
        <SkipUserOOBE>true</SkipUserOOBE>
      </OOBE>
      <TimeZone>$TimeZone</TimeZone>
    </component>
  </settings>
</unattend>
"@

    $unattendXml | Set-Content -Path $unattend -Encoding UTF8
}


function Remove-CachedPrepScript {
    $scriptRoot = if ($PSScriptRoot) {
        $PSScriptRoot
    } elseif ($MyInvocation.MyCommand.Path) {
        Split-Path -Parent $MyInvocation.MyCommand.Path
    } else {
        (Get-Location).Path
    }

    $cachedScript = Join-Path -Path $scriptRoot -ChildPath 'OSD_Gold_Image_Prep_Script.ps1'

    try {
        if (Test-Path -LiteralPath $cachedScript) {
            Remove-Item -LiteralPath $cachedScript -Force -ErrorAction Stop
            Logwrite ("Removed cached prep script before Sysprep: {0}" -f $cachedScript)
        }
    }
    catch {
        Logwrite ("WARNING: Could not remove cached prep script {0}: {1}" -f $cachedScript, $_.Exception.Message)
        Write-Host ("WARNING: Could not remove {0}" -f $cachedScript) -ForegroundColor Yellow
    }
}

function Invoke-FinalSysprep {
    $unattend = "C:\Program Files\Cloudbase Solutions\Cloudbase-Init\conf\unattend.xml"
    $sysprep  = "C:\Windows\System32\Sysprep\Sysprep.exe"

    if (-not (Test-Path $sysprep)) {
        Write-Host "ERROR: Sysprep not found at $sysprep. Cannot continue." -ForegroundColor Red
        Logwrite "ERROR: Sysprep not found."
        exit 1
    }

    Write-Host "Running Sysprep. Once session disconnects, confirm the instance is STOPPED, then convert it to a custom image." -ForegroundColor Green
    Write-Host "Add tag oci:desktops:is_desktop_image=True" -ForegroundColor Green

    & $sysprep /generalize /oobe /shutdown /unattend:$unattend
}

# -------------------------------------------------------------------
# Main flow
# -------------------------------------------------------------------

Write-Host ""
do {
    $skipUpdatesChoice = (Read-Host "Check Windows Updates before imaging? (Y/N)").Trim().ToUpper()
} until ($skipUpdatesChoice -in @('Y','N'))

$skipWindowsUpdateCheck = ($skipUpdatesChoice -eq 'N')
Ensure-NoPendingUpdates -SkipCheck:$skipWindowsUpdateCheck
Ensure-NoPendingReboot
Ensure-EnableRdpScript
Set-DefaultUserVisualFx
Remove-OldVfxLogonTrigger
Setup-FirstUserRdpRestriction

$allowSecretsModes = $false

# image mode / join mode prompts
# tags/vault/manual validation



Write-Host ""
Write-Host "Select image mode:" -ForegroundColor Cyan
Write-Host "1. OSD image only (no automatic AD or Entra ID join)"
Write-Host "2. OSD image with automatic AD domain join on deployed instances"
Write-Host "3. OSD image with automatic Entra ID join using a PPKG during specialize"

do {
    $imageMode = (Read-Host "Enter 1, 2, or 3").Trim()
} while ($imageMode -notin @('1','2','3'))

$freeFormTags = $null
$finalTimeZone = $null
$entraPpkgPath = $null
$entraPpkgSourcePath = $null

if ($imageMode -eq '2') {
    $pwsh7Path = "C:\Program Files\PowerShell\7\pwsh.exe"
    $pwsh7Installed = Test-PowerShell7Installed
    $allowSecretsModes = $pwsh7Installed

    Write-Host ""
    if ($pwsh7Installed) {
        Write-Host "PowerShell 7 is already installed." -ForegroundColor Green

        do {
            $upgradePwshChoice = (Read-Host "Check for the latest PowerShell 7 now? (Y/N)").Trim().ToUpper()
        } until ($upgradePwshChoice -in @('Y','N'))

        if ($upgradePwshChoice -eq 'Y') {
            Ensure-PowerShell7Latest -TempDir $tmp_dir
            $pwsh7Installed = Test-PowerShell7Installed
        } else {
            Write-Host "Skipping PowerShell 7 download/upgrade." -ForegroundColor Yellow
            Logwrite "Skipped PowerShell 7 download/upgrade by user choice."
        }
    }
    else {
        Write-Host "PowerShell 7 is not installed." -ForegroundColor Yellow

        do {
            $installPwshChoice = (Read-Host "Download and install PowerShell 7 for OCI secrets support? (Y/N)").Trim().ToUpper()
        } until ($installPwshChoice -in @('Y','N'))

        if ($installPwshChoice -eq 'Y') {
            Ensure-PowerShell7Latest -TempDir $tmp_dir
            $pwsh7Installed = Test-PowerShell7Installed
        } else {
            Write-Host "Skipping PowerShell 7 download/install." -ForegroundColor Yellow
            Logwrite "Skipped PowerShell 7 download/install by user choice."
        }
    }

    $allowSecretsModes = $pwsh7Installed

    if ($allowSecretsModes) {
        Write-Host "Select AD domain join mode:" -ForegroundColor Cyan
        Write-Host "1. Instance tags"
        Write-Host "2. Manual OCI Vault secret OCIDs"
        Write-Host "3. Manual AD credentials"

        do {
            $joinModeChoice = (Read-Host "Enter 1, 2, or 3").Trim()
        } while ($joinModeChoice -notin @('1','2','3'))
    }
    else {
        Write-Host "OCI Vault and tag-based secret modes are unavailable because PowerShell 7 was skipped or is not installed." -ForegroundColor Yellow
        Write-Host "Only manual AD credentials are available." -ForegroundColor Yellow

        do {
            $joinModeChoice = (Read-Host "Enter 1 to continue with manual AD credentials").Trim()
        } while ($joinModeChoice -ne '1')

        $joinModeChoice = '3'
    }

    switch ($joinModeChoice) {
        '1' {
            $joinMode = "tags"
            $freeFormTags = read_tags

            if (-not $freeFormTags) {
				Write-ErrorExit `
					-Message "Could not read instance freeFormTags from metadata." `
					-Cause "OCI metadata service did not return freeFormTags." `
					-Fix "Verify metadata service access and confirm the required instance tags exist." `
					-Code 22
			}

            if (-not ($freeFormTags.'osd_ib:ad_user_ocid' -and
			  $freeFormTags.'osd_ib:ad_pass_ocid' -and
			  $freeFormTags.'osd_ib:ad_fqdn' -and
			  $freeFormTags.'osd_ib:ad_ou')) {
				Write-ErrorExit `
					-Message "Required AD tags were not found on the instance." `
					-Cause "One or more required freeFormTags are missing." `
					-Fix "Add osd_ib:ad_user_ocid, osd_ib:ad_pass_ocid, osd_ib:ad_fqdn, and osd_ib:ad_ou to the instance." `
					-Code 23
			}

            Ensure-OCISecretsModule -TempDir $tmp_dir

            Write-Host "Validating OCI Vault secret access..." -ForegroundColor Cyan

			Test-OCISecretAccess -SecretOCID $freeFormTags.'osd_ib:ad_user_ocid' -SecretPurpose "AD username" -ValidateAsADUsername
			Test-OCISecretAccess -SecretOCID $freeFormTags.'osd_ib:ad_pass_ocid' -SecretPurpose "AD password"

			Test-ADDomainReachability -DomainFQDN $freeFormTags.'osd_ib:ad_fqdn' -DomainControllerList $freeFormTags.'osd_ib:ad_dc'

			$tagUserValue = Get-ValidatedOCISecretValue -SecretOCID $freeFormTags.'osd_ib:ad_user_ocid' -SecretPurpose "AD username"
			$tagPassValue = Get-ValidatedOCISecretValue -SecretOCID $freeFormTags.'osd_ib:ad_pass_ocid' -SecretPurpose "AD password"

			$firstTagDC = ""
			if (-not [string]::IsNullOrWhiteSpace($freeFormTags.'osd_ib:ad_dc')) {
				$firstTagDC = (($freeFormTags.'osd_ib:ad_dc').Split(",")[0]).Trim()
			}

			Test-ADCredential -DomainFQDN $freeFormTags.'osd_ib:ad_fqdn' -Username $tagUserValue -Password $tagPassValue -DomainController $firstTagDC

            domainjoin_file_create -JoinMode $joinMode -freeFormTags $freeFormTags

            $finalTimeZone = if ($script:ad_timezone) { $script:ad_timezone } else { "UTC" }
        }

        '2' {
            $joinMode = "vault"

            Ensure-OCISecretsModule -TempDir $tmp_dir

            $vaultUserSecretOCID = (Read-Host -Prompt "Secret OCID for AD join username").Trim()
            $vaultPassSecretOCID = (Read-Host -Prompt "Secret OCID for AD join password").Trim()

			Write-Host "Validating OCI Vault secret access..." -ForegroundColor Cyan

			Test-OCISecretAccess -SecretOCID $vaultUserSecretOCID -SecretPurpose "AD username" -ValidateAsADUsername
			Test-OCISecretAccess -SecretOCID $vaultPassSecretOCID -SecretPurpose "AD password"

			$vaultDomainFQDN = (Read-Host -Prompt "Domain FQDN (e.g. example.com)").Trim()
			$vaultDCList = (Read-Host -Prompt "Domain controller FQDN(s) (optional, comma-separated; Enter to skip)").Trim()

			Test-ADDomainReachability -DomainFQDN $vaultDomainFQDN -DomainControllerList $vaultDCList

			$vaultUserValue = Get-ValidatedOCISecretValue -SecretOCID $vaultUserSecretOCID -SecretPurpose "AD username"
			$vaultPassValue = Get-ValidatedOCISecretValue -SecretOCID $vaultPassSecretOCID -SecretPurpose "AD password"

			$firstVaultDC = ""
			if (-not [string]::IsNullOrWhiteSpace($vaultDCList)) {
				$firstVaultDC = ($vaultDCList.Split(",")[0]).Trim()
			}

			Test-ADCredential -DomainFQDN $vaultDomainFQDN -Username $vaultUserValue -Password $vaultPassValue -DomainController $firstVaultDC		

            domainjoin_file_create -JoinMode $joinMode `
                -freeFormTags $null `
                -VaultUserSecretOCID $vaultUserSecretOCID `
                -VaultPassSecretOCID $vaultPassSecretOCID `
                -DomainFQDN $vaultDomainFQDN `
                -DomainControllerList $vaultDCList

            $finalTimeZone = input_timezone
        }

        '3' {
            $joinMode = "manual"

            $manualUsername = (Read-Host -Prompt "AD username").Trim()
            $manualPassword = (Read-Host -Prompt "AD password").Trim()
            $manualDomainFQDN = (Read-Host -Prompt "Domain FQDN (e.g. example.com)").Trim()
            $manualDCList = (Read-Host -Prompt "Domain controller FQDN(s) (optional, comma-separated; Enter to skip)").Trim()

            Test-ADDomainReachability -DomainFQDN $manualDomainFQDN -DomainControllerList $manualDCList

            domainjoin_file_create -JoinMode $joinMode `
                -freeFormTags $null `
                -DomainFQDN $manualDomainFQDN `
                -DomainControllerList $manualDCList

            $finalTimeZone = if ($script:ad_timezone) { $script:ad_timezone } else { "UTC" }
        }
    }

    script_file_create
    files_check
    cloudbaseinit_copy_wrapper
}
elseif ($imageMode -eq '3') {
    Write-Host ""
    $entraPpkgSourcePath = Get-EntraProvisioningPackageSourcePath
    $entraPpkgPath = Stage-EntraProvisioningPackage -SourcePath $entraPpkgSourcePath
    $finalTimeZone = input_timezone
    Logwrite ("Entra ID join selected. Using staged provisioning package at {0}." -f $entraPpkgPath)
}
else {
    $finalTimeZone = input_timezone
    Logwrite ("Image-only mode selected. Unattend timezone set to {0}" -f $finalTimeZone)

}

Write-UnattendXml -TimeZone $finalTimeZone -EntraPpkgPath $entraPpkgPath -EntraPpkgSourcePath $entraPpkgSourcePath

Invoke-OptionalDismCleanup

Write-Host ""
do {
    $removeAppxAtEnd = (Read-Host "Do you want to remove AppX packages for all users before Sysprep? (Y/N)").Trim()
} while ($removeAppxAtEnd -notmatch '^[YyNn]$')

Logwrite ("Remove AppX before sysprep choice: {0}" -f $removeAppxAtEnd)

Write-Host ""
do {
    $removeCurrentUser = (Read-Host "Do you want to remove the currently logged-in local user '$Env:USERNAME' before Sysprep? (Y/N)").Trim()
} while ($removeCurrentUser -notmatch '^[YyNn]$')

Logwrite ("Remove current local user before sysprep choice: {0}" -f $removeCurrentUser)

Write-Host ""
do {
    $sysprepgo = (Read-Host -Prompt 'Continue with sysprep and shutting down (y/n)').Trim()
} while ($sysprepgo -notmatch '^[YyNn]$')

Logwrite ("Continue with sysprep and shutting down (y/n): {0}" -f $sysprepgo)

if ($sysprepgo -match '^[Yy]$') {

    if ($removeAppxAtEnd -match '^[Yy]$') {
        Invoke-OptionalAppxRemoval
    } else {
        Write-Host "Skipping AppX package removal." -ForegroundColor Yellow
        Logwrite "Skipped AppX removal."
    }

    if ($removeCurrentUser -match '^[Yy]$') {
        Remove-CurrentLocalUserBestEffort
    } else {
        Write-Host "Skipping removal of current local user." -ForegroundColor Yellow
        Logwrite "Skipped removal of current local user."
    }

    if ($imageMode -eq '1') {
        Cleanup-ImagePrepArtifacts
    }

    Remove-CachedPrepScript

    Start-Sleep -Seconds 2
    Invoke-FinalSysprep

} else {
    Write-Host ""
    Write-Host "You selected NO; sysprep will not run. Exiting tool."
    Logwrite "You selected NO; sysprep will not run. Exiting tool."
    exit 13
}
