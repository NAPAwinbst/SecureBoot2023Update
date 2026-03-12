<#
.SYNOPSIS
    Intune Remediation Script - Secure Boot 2023 Certificate Update
.DESCRIPTION
    Sets the registry keys to trigger Secure Boot certificate deployment
    and opt in to Microsoft's Controlled Feature Rollout.

    This script is safe to run on devices that have already been updated —
    if status is "Updated" or the cert is already present, it skips
    the update trigger to avoid unnecessary processing.

    Exit 0 = Remediation applied, already updated, in progress, or not applicable (VM)
    Exit 1 = Remediation failed, Secure Boot disabled, or firmware error (needs investigation)
.NOTES
    Deploy as: Remediation script in Intune Remediations
    Run as: System (64-bit)
    Version: 3.2
#>

$sbPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot'
$sbServicingPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing'

# Safety check: only proceed if Secure Boot is enabled
try {
    $secureBootEnabled = Confirm-SecureBootUEFI
} catch {
    $secureBootEnabled = $false
}

if (-not $secureBootEnabled) {
    Write-Output "Secure Boot is not enabled. Cannot apply certificate updates. Manual intervention required."
    exit 1
}

# Check if running in a virtual machine — hypervisors block UEFI variable writes
# Prefer excluding VMs from assignment; remediation exits successfully to avoid noise if they slip in
try {
    $cs = Get-CimInstance Win32_ComputerSystem
    $isVM = $cs.Model -match 'Virtual Machine' -or $cs.Manufacturer -match 'VMware|QEMU|Xen|VirtualBox|innotek'
} catch {
    $isVM = $false
}

if ($isVM) {
    Write-Output "Virtual machine detected ($($cs.Manufacturer) / $($cs.Model)). Secure Boot variable writes are hypervisor-controlled. This remediation intentionally exits successfully to avoid repeated noise. Exclude VMs or handle via VM-specific process."
    exit 0
}

# Check if device is in an error state — don't retry, it needs manual investigation
try {
    $errVal = Get-ItemProperty -Path $sbServicingPath -Name 'UEFICA2023Error' -ErrorAction SilentlyContinue
    if ($null -ne $errVal -and $null -ne $errVal.UEFICA2023Error -and $errVal.UEFICA2023Error -ne 0) {
        Write-Output "UEFICA2023Error = $($errVal.UEFICA2023Error). Device has a firmware-level failure. Setting registry keys will not fix this. Investigate: check BIOS version, Event Viewer (1795/1796), and contact OEM if needed."
        exit 1
    }
} catch { }

# Check UEFICA2023Status — this is the authoritative servicing key from Microsoft
$servicingKeyExists = Test-Path $sbServicingPath
try {
    $status = Get-ItemProperty -Path $sbServicingPath -Name 'UEFICA2023Status' -ErrorAction SilentlyContinue
    if ($status -and $status.UEFICA2023Status -eq 'Updated') {
        Write-Output "UEFICA2023Status = Updated. Device already compliant. No action needed."
        exit 0
    }
    if ($status -and $status.UEFICA2023Status -eq 'InProgress') {
        Write-Output "UEFICA2023Status = InProgress. Update is already running. No action needed."
        exit 0
    }
} catch { }

# Best-effort firmware check — ASCII parsing of UEFI signature databases is not guaranteed
# to work on all OEM implementations. Only used as a fallback when the Servicing key is
# absent or has no status (e.g. device updated via BIOS without Windows involvement)
if (-not $servicingKeyExists -or ($null -eq $status) -or ($null -eq $status.UEFICA2023Status)) {
    try {
        $db = Get-SecureBootUEFI -Name db
        $dbString = [System.Text.Encoding]::ASCII.GetString($db.Bytes)
        $dbHas2023 = ($dbString -match 'Windows UEFI CA 2023')

        $kek = Get-SecureBootUEFI -Name kek
        $kekString = [System.Text.Encoding]::ASCII.GetString($kek.Bytes)
        $kekHas2023 = ($kekString -match 'Microsoft Corporation KEK 2K CA 2023')

        if ($dbHas2023 -and $kekHas2023) {
            Write-Output "Both 2023 certificates found in firmware (best-effort check). No action needed."
            exit 0
        }
    } catch { }
}

# --- Log current state for troubleshooting ---
try {
    $currentAv = Get-ItemProperty -Path $sbPath -Name 'AvailableUpdates' -ErrorAction SilentlyContinue
    $currentStatus = Get-ItemProperty -Path $sbServicingPath -Name 'UEFICA2023Status' -ErrorAction SilentlyContinue
    $currentErr = Get-ItemProperty -Path $sbServicingPath -Name 'UEFICA2023Error' -ErrorAction SilentlyContinue
    $currentOptIn = Get-ItemProperty -Path $sbPath -Name 'MicrosoftUpdateManagedOptIn' -ErrorAction SilentlyContinue
    $currentOptOut = Get-ItemProperty -Path $sbPath -Name 'HighConfidenceOptOut' -ErrorAction SilentlyContinue
    $stateMsg = "Current state: " +
        "AvailableUpdates=$( if ($null -ne $currentAv.AvailableUpdates) { '0x{0:X}' -f $currentAv.AvailableUpdates } else { 'not set' } ), " +
        "UEFICA2023Status=$( if ($null -ne $currentStatus.UEFICA2023Status) { $currentStatus.UEFICA2023Status } else { 'not set' } ), " +
        "UEFICA2023Error=$( if ($null -ne $currentErr.UEFICA2023Error) { $currentErr.UEFICA2023Error } else { 'none' } ), " +
        "OptIn=$( if ($null -ne $currentOptIn.MicrosoftUpdateManagedOptIn) { $currentOptIn.MicrosoftUpdateManagedOptIn } else { 'not set' } ), " +
        "OptOut=$( if ($null -ne $currentOptOut.HighConfidenceOptOut) { $currentOptOut.HighConfidenceOptOut } else { 'not set' } )"
    if (-not $servicingKeyExists) { $stateMsg += " [Servicing key does not exist — update has never been initiated on this device]" }
    elseif ($null -eq $currentStatus.UEFICA2023Status) { $stateMsg += " [Servicing key exists but status is not set — update may not have started yet]" }
    Write-Output $stateMsg
} catch { }

# --- Apply registry keys ---
$errors = @()

# 1. Set AvailableUpdates to 0x5944 (full certificate deployment sequence)
#    Triggers: KEK 2023, UEFI CA 2023, Production PCA, and boot manager update
#    Skip if already non-zero — update is already in progress and resetting would delay it
try {
    $av = Get-ItemProperty -Path $sbPath -Name 'AvailableUpdates' -ErrorAction SilentlyContinue
    if ($null -eq $av -or $av.AvailableUpdates -eq 0) {
        Set-ItemProperty -Path $sbPath -Name 'AvailableUpdates' -Value 0x5944 -Type DWord -Force
        Write-Output "Set AvailableUpdates = 0x5944"
    } else {
        Write-Output "AvailableUpdates already set to $('0x{0:X}' -f $av.AvailableUpdates) — update in progress, skipping reset"
    }
} catch {
    $errors += "Failed to set AvailableUpdates: $_"
}

# 2. Set MicrosoftUpdateManagedOptIn to 1 (enroll in Controlled Feature Rollout)
#    Allows Microsoft to assist via Windows Update for high-confidence devices
try {
    Set-ItemProperty -Path $sbPath -Name 'MicrosoftUpdateManagedOptIn' -Value 1 -Type DWord -Force
    Write-Output "Set MicrosoftUpdateManagedOptIn = 1"
} catch {
    $errors += "Failed to set MicrosoftUpdateManagedOptIn: $_"
}

# 3. Ensure HighConfidenceOptOut is 0 (do not block automatic updates)
try {
    Set-ItemProperty -Path $sbPath -Name 'HighConfidenceOptOut' -Value 0 -Type DWord -Force
    Write-Output "Set HighConfidenceOptOut = 0"
} catch {
    # Non-fatal — log but continue
    Write-Output "WARNING: Failed to set HighConfidenceOptOut: $_"
}

# Check for critical errors
if ($errors.Count -gt 0) {
    foreach ($e in $errors) { Write-Output "ERROR: $e" }
    exit 1
}

# --- Post-write state snapshot (validates keys were actually written) ---
try {
    $postAv = Get-ItemProperty -Path $sbPath -Name 'AvailableUpdates' -ErrorAction SilentlyContinue
    $postOptIn = Get-ItemProperty -Path $sbPath -Name 'MicrosoftUpdateManagedOptIn' -ErrorAction SilentlyContinue
    $postOptOut = Get-ItemProperty -Path $sbPath -Name 'HighConfidenceOptOut' -ErrorAction SilentlyContinue
    Write-Output "Post-write state: AvailableUpdates=$( if ($null -ne $postAv.AvailableUpdates) { '0x{0:X}' -f $postAv.AvailableUpdates } else { 'not set' } ), OptIn=$( if ($null -ne $postOptIn.MicrosoftUpdateManagedOptIn) { $postOptIn.MicrosoftUpdateManagedOptIn } else { 'not set' } ), OptOut=$( if ($null -ne $postOptOut.HighConfidenceOptOut) { $postOptOut.HighConfidenceOptOut } else { 'not set' } )"
} catch { }

Write-Output "Remediation complete. The Secure-Boot-Update scheduled task will process on its normal schedule. At least one reboot is required to finalize. Optional: to expedite, run Start-ScheduledTask -TaskName '\Microsoft\Windows\PI\Secure-Boot-Update'"
exit 0
