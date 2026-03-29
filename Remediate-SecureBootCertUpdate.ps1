<#
.SYNOPSIS
    Intune Remediation Script - Secure Boot 2023 Certificate Update
.DESCRIPTION
    Sets the registry keys to trigger Secure Boot certificate deployment,
    opts in to Microsoft's Controlled Feature Rollout, and starts the
    Secure Boot update scheduled task to expedite processing.

    This script is safe to run on devices that have already been updated --
    if status is "Updated" or the cert is already present, it skips
    the update trigger to avoid unnecessary processing.

    Exit 0 = Remediation applied, already updated, in progress, or not applicable (VM)
    Exit 1 = Remediation failed, Secure Boot disabled, firmware error, or prerequisites not met
.NOTES
    Deploy as: Remediation script in Intune Remediations
    Run as: System (64-bit)
    Version: 4.0
    Based on original work by @MrTbone_se (T-bone Granheden) - MIT License
#>

#region ---------------------------------------------------[Functions]------------------------------------------------------------
function Get-SecureBootCertSubjects {
<#
.SYNOPSIS
    Parse Secure Boot database signatures and return them as objects
.DESCRIPTION
    Parses the EFI signature database and returns an array of PSCustomObjects
    with proper X.509 certificate parsing.
.NOTES
    Original Author: @MrTbone_se (T-bone Granheden)
#>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Database
    )
    $db = (Get-SecureBootUEFI -Name $Database).Bytes
    $EFI_CERT_X509_GUID = [guid]"a5c059a1-94e4-4aa7-87b5-ab155c2bf072"
    $EFI_CERT_SHA256_GUID = [guid]"c1c41626-504c-4092-aca9-41f936934328"
    $signatures = @()
    for ($o = 0; $o -lt $db.Length; ) {
        $guid = [Guid][Byte[]]$db[$o..($o+15)]
        $signatureListSize = [BitConverter]::ToUInt32($db, $o+16)
        $signatureSize = [BitConverter]::ToUInt32($db, $o+24)
        $signatureCount = ($signatureListSize - 28) / $signatureSize
        $so = $o + 28
        for ($i = 0; $i -lt $signatureCount; $i++) {
            $signatureOwner = [Guid][Byte[]]$db[$so..($so+15)]
            if ($guid -eq $EFI_CERT_X509_GUID) {
                $certBytes = $db[($so+16)..($so+16+$signatureSize-1)]
                try {
                    $cert = if ($PSEdition -eq "Core") {
                        [System.Security.Cryptography.X509Certificates.X509Certificate]::new([Byte[]]$certBytes)
                    } else {
                        $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                        $c.Import([Byte[]]$certBytes)
                        $c
                    }
                    $signatures += [PSCustomObject]@{SignatureOwner=$signatureOwner; SignatureSubject=$cert.Subject; Signature=$cert; SignatureType=$guid}
                } catch {
                    $signatures += [PSCustomObject]@{SignatureOwner=$signatureOwner; SignatureSubject="Failed to parse cert"; Signature=$null; SignatureType=$guid}
                }
            } elseif ($guid -eq $EFI_CERT_SHA256_GUID) {
                $sha256Hash = ([Byte[]]$db[($so+16)..($so+47)] | ForEach-Object { $_.ToString('X2') }) -join ''
                $signatures += [PSCustomObject]@{SignatureOwner=$signatureOwner; Signature=$sha256Hash; SignatureType=$guid}
            } else {
                $unknownData = [Byte[]]$db[($so+16)..($so+16+$signatureSize-1)]
                $signatures += [PSCustomObject]@{SignatureOwner=$signatureOwner; SignatureSubject="Unknown signature type"; Signature=$unknownData; SignatureType=$guid}
            }
            $so += $signatureSize
        }
        $o += $signatureListSize
    }
    return $signatures
}
#endregion

#region ---------------------------------------------------[Configuration]-------------------------------------------------------
# OS versions and the required July 2024 patch level for Secure Boot Update prerequisite
$OSversions = @(
    @{ Name='Insider'; Build=26200; Patch=0 }
    @{ Name='24H2'; Build=26100; Patch=1150 }
    @{ Name='23H2'; Build=22631; Patch=3880 }
    @{ Name='22H2'; Build=22621; Patch=3880 }
    @{ Name='21H2'; Build=22000; Patch=3079 }
    @{ Name='22H2(Win10)'; Build=19045; Patch=4651 }
    @{ Name='21H2(Win10)'; Build=19044; Patch=4651 }
    @{ Name='1809(LTSC)'; Build=17763; Patch=6054 }
    @{ Name='1609(LTSC)'; Build=14393; Patch=7259 }
)
$RemediateTaskName = "\Microsoft\Windows\PI\Secure-Boot-Update"
#endregion

#region ---------------------------------------------------[Paths]---------------------------------------------------------------
$sbPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot'
$sbServicingPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing'
#endregion

#region ---------------------------------------------------[Prerequisites check]-------------------------------------------------
# Validate 64-bit PowerShell
if ([IntPtr]::Size -ne 8) {
    Write-Output "ERROR: Script requires 64-bit PowerShell (running $([IntPtr]::Size * 8)-bit)."
    exit 1
}

# Validate elevated privileges (SYSTEM or Administrator)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isElevated = $identity.User.Value -eq "S-1-5-18" -or ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isElevated) {
    Write-Output "ERROR: Script requires elevated privileges (SYSTEM or Administrator)."
    exit 1
}
#endregion

#region ---------------------------------------------------[Safety checks]-------------------------------------------------------
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

# Check if running in a virtual machine -- hypervisors block UEFI variable writes
# Prefer excluding VMs from assignment; remediation exits successfully to avoid noise if they slip in
try {
    $cs = Get-CimInstance Win32_ComputerSystem
    $isVM = $cs.Model -match 'Virtual Machine|Virtual|VMware|VirtualBox|Hyper-V|QEMU|Parallels' -or $cs.Manufacturer -match 'VMware|QEMU|Xen|VirtualBox|innotek'
} catch {
    $isVM = $false
}

if ($isVM) {
    Write-Output "Virtual machine detected ($($cs.Manufacturer) / $($cs.Model)). Secure Boot variable writes are hypervisor-controlled. This remediation intentionally exits successfully to avoid repeated noise. Exclude VMs or handle via VM-specific process."
    exit 0
}
#endregion

#region ---------------------------------------------------[OS patch prerequisite check]-----------------------------------------
try {
    $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
    $Build = if ($cv.CurrentBuildNumber) { try {[int]$cv.CurrentBuildNumber} catch { $null } } elseif ($cv.CurrentBuild) { try {[int]$cv.CurrentBuild} catch { $null } } else { $null }
    $Patch = if ($null -ne $cv.UBR) { try {[int]$cv.UBR} catch { $null } } else { $null }
    $OSversionsSorted = $OSversions | Sort-Object { [int]$_.Build } -Descending
    $matchedOS = $OSversionsSorted | Where-Object { ($Build -ne $null) -and ([int]$_.Build -le $Build) } | Select-Object -First 1
    $osPatchOk = $false
    if ($matchedOS) {
        if ($matchedOS['Patch'] -eq 0) { $osPatchOk = $true }
        elseif ($null -ne $Patch -and $Patch -ge $matchedOS['Patch']) { $osPatchOk = $true }
    }
    if (-not $osPatchOk -and $null -ne $matchedOS) {
        Write-Output "OS patch prerequisite not met. Current: $($matchedOS['Name']) $Build.$Patch, Required patch level: $($matchedOS['Patch']). Install the July 2024 cumulative update first."
        exit 1
    }
} catch { }
#endregion

#region ---------------------------------------------------[Error state check]---------------------------------------------------
# Check if device is in an error state -- don't retry, it needs manual investigation
try {
    $errVal = Get-ItemProperty -Path $sbServicingPath -Name 'UEFICA2023Error' -ErrorAction SilentlyContinue
    if ($null -ne $errVal -and $null -ne $errVal.UEFICA2023Error -and $errVal.UEFICA2023Error -ne 0) {
        Write-Output "UEFICA2023Error = $($errVal.UEFICA2023Error). Device has a firmware-level failure. Setting registry keys will not fix this. Investigate: check BIOS version, Event Viewer (1795/1796), and contact OEM if needed."
        exit 1
    }
} catch { }
#endregion

#region ---------------------------------------------------[Already-compliant checks]--------------------------------------------
# Check UEFICA2023Status -- this is the authoritative servicing key from Microsoft
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

# Fallback firmware cert check using proper X.509 parsing
if (-not $servicingKeyExists -or ($null -eq $status) -or ($null -eq $status.UEFICA2023Status) -or $status.UEFICA2023Status -eq 'NotStarted') {
    try {
        $dbcerts = Get-SecureBootCertSubjects -Database db
        $dbHas2023 = [bool]($dbcerts | Where-Object { $_.SignatureSubject -match 'Windows UEFI CA 2023' })

        $KEKcerts = Get-SecureBootCertSubjects -Database kek
        $kekHas2023 = [bool]($KEKcerts | Where-Object { $_.SignatureSubject -match 'KEK 2K CA 2023' })

        if ($dbHas2023 -and $kekHas2023) {
            Write-Output "Both 2023 certificates found in firmware (X.509 cert check). No action needed."
            exit 0
        }
    } catch { }
}
#endregion

#region ---------------------------------------------------[Log current state]---------------------------------------------------
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
    if (-not $servicingKeyExists) { $stateMsg += " [Servicing key does not exist -- update has never been initiated on this device]" }
    elseif ($null -eq $currentStatus.UEFICA2023Status) { $stateMsg += " [Servicing key exists but status is not set -- update may not have started yet]" }
    Write-Output $stateMsg
} catch { }
#endregion

#region ---------------------------------------------------[Apply registry keys]-------------------------------------------------
$errors = @()

# 1. Set AvailableUpdates to 0x5944 (full certificate deployment sequence)
#    Triggers: KEK 2023, UEFI CA 2023, Production PCA, and boot manager update
#    Skip if already non-zero -- update is already in progress and resetting would delay it
try {
    $av = Get-ItemProperty -Path $sbPath -Name 'AvailableUpdates' -ErrorAction SilentlyContinue
    if ($null -eq $av -or $av.AvailableUpdates -eq 0) {
        Set-ItemProperty -Path $sbPath -Name 'AvailableUpdates' -Value 0x5944 -Type DWord -Force
        Write-Output "Set AvailableUpdates = 0x5944"
    } else {
        Write-Output "AvailableUpdates already set to $('0x{0:X}' -f $av.AvailableUpdates) -- update in progress, skipping reset"
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
    # Non-fatal -- log but continue
    Write-Output "WARNING: Failed to set HighConfidenceOptOut: $_"
}

# Check for critical errors before proceeding
if ($errors.Count -gt 0) {
    foreach ($e in $errors) { Write-Output "ERROR: $e" }
    exit 1
}
#endregion

#region ---------------------------------------------------[Start scheduled task]------------------------------------------------
# Explicitly start the Secure Boot update scheduled task to expedite processing
try {
    Start-ScheduledTask -TaskName $RemediateTaskName -ErrorAction Stop
    Write-Output "Secure Boot update scheduled task started ($RemediateTaskName)."
} catch {
    # Non-fatal -- task may not exist on all OS versions, or may already be running
    Write-Output "WARNING: Could not start scheduled task '$RemediateTaskName': $_. The update will process on its normal schedule or after reboot."
}
#endregion

#region ---------------------------------------------------[Post-write validation]-----------------------------------------------
try {
    $postAv = Get-ItemProperty -Path $sbPath -Name 'AvailableUpdates' -ErrorAction SilentlyContinue
    $postOptIn = Get-ItemProperty -Path $sbPath -Name 'MicrosoftUpdateManagedOptIn' -ErrorAction SilentlyContinue
    $postOptOut = Get-ItemProperty -Path $sbPath -Name 'HighConfidenceOptOut' -ErrorAction SilentlyContinue
    Write-Output "Post-write state: AvailableUpdates=$( if ($null -ne $postAv.AvailableUpdates) { '0x{0:X}' -f $postAv.AvailableUpdates } else { 'not set' } ), OptIn=$( if ($null -ne $postOptIn.MicrosoftUpdateManagedOptIn) { $postOptIn.MicrosoftUpdateManagedOptIn } else { 'not set' } ), OptOut=$( if ($null -ne $postOptOut.HighConfidenceOptOut) { $postOptOut.HighConfidenceOptOut } else { 'not set' } )"
} catch { }

Write-Output "Remediation complete. At least one reboot is required to finalize the Secure Boot certificate update."
exit 0
#endregion
