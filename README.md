# OSD Gold Image Prep Script

A PowerShell helper for preparing a Windows gold image for Oracle Cloud Infrastructure (OCI) Secure Desktops.

## Included files

- **OSD_Gold_Image_Prep_Launcher.ps1** downloads the latest full script from this repository, caches it beside the launcher, and starts it. If GitHub is unavailable, it can use the existing cached copy.
- **OSD_Gold_Image_Prep_Script.ps1** is the interactive image preparation script.

## What the preparation script does

Based on your selections, it can:

- Check Windows Update status and detect pending reboots.
- Enable Remote Desktop and apply image-preparation settings.
- Prepare an image for OCI Secure Desktops without a directory join, with Active Directory domain join, or with Entra ID join using a provisioning package.
- Use instance tags, OCI Vault secret OCIDs, or manually entered credentials for AD join configuration.
- Create Cloudbase-Init configuration and Sysprep unattend files.
- Optionally remove AppX packages and the current local user before Sysprep.
- Run Sysprep with generalize, OOBE, and shutdown options.
- After Sysprep is confirmed, remove the launcher and cached full script from the launch folder.

## Quick start

1. Download **OSD_Gold_Image_Prep_Launcher.ps1**.
2. Place it in the folder where you want the script cache to be stored.
3. Run PowerShell as Administrator and execute:

    .\OSD_Gold_Image_Prep_Launcher.ps1

4. Follow the prompts and carefully review all selections before confirming Sysprep.

> **Important:** Sysprep generalizes the image and shuts down Windows. Test this process on a non-production image first.

## Requirements

- A Windows image intended for OCI Secure Desktops.
- PowerShell with Administrator privileges.
- Internet access to GitHub for launcher updates.
- Cloudbase-Init installed and configured for the OCI Secure Desktops workflow.
- For Entra ID join, place exactly one .ppkg provisioning package beside the full preparation script before running it.

## Security notes

Do not commit passwords, tokens, Vault secrets, provisioning packages, or other credentials to this repository. Use your organization's approved secret-management method whenever possible.

## Disclaimer

This project is an independent community tool published by **TestThingsTech**. It is **not** an Oracle product, and it is not affiliated with, endorsed by, or supported by Oracle. It is provided as-is without warranty.

The same disclaimer applies to other tools published by TestThingsTech. Validate this tool in your own environment before production use.
