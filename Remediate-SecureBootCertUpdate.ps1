<#
.SYNOPSIS
    Intune Remediation Script - Secure Boot 2023 Certificate Update
.DESCRIPTION
    Sets the registry keys to trigger Secure Boot certificate deployment,
    opts in to Microsoft's Controlled Feature Rollout, verifies BitLocker
    recovery key escrow, and starts the Secure Boot update scheduled task.

    STAGED DEPLOYMENT: This script uses a configurable AvailableUpdates value.
    Adjust $AvailableUpdatesValue below to control which update phase is triggered:
      Phase 1 (conservative): 0x44  = Add UEFI CA 2023 + KEK 2023 certs only
      Phase 2 (intermediate): 0x340 = Phase 1 + Boot Manager + SVN update
      Phase 3 (full):         0x5944 = All updates including revocations

    This script is safe to run on devices that have already been updated --
    if status is "Updated" or the cert is already present, it skips
    the update trigger to avoid unnecessary processing.

    If AvailableUpdates is already set to a HIGHER value (e.g. 0x5944 from a
    previous script version), the existing value is preserved to avoid
    interrupting an in-progress update sequence.

    Exit 0 = Remediation applied, already updated, in progress, or not applicable (VM)
    Exit 1 = Remediation failed, Secure Boot disabled, firmware error, BitLocker
             not escrowed, or prerequisites not met
.NOTES
    Deploy as: Remediation script in Intune Remediations
    Run as: System (64-bit)
    Version: 5.1
    Based on original work by @MrTbone_se (T-bone Granheden) - MIT License
#>

#region ---------------------------------------------------[Functions]------------------------------------------------------------
# IMPORTANT: This function is duplicated in the Detection script - keep both in sync.
# Function version: 2 -- bump when changing; keep identical across both scripts.
function Get-SecureBootCertSubjects {
<#
.SYNOPSIS
    Parse Secure Boot database signatures and return them as objects
.DESCRIPTION
    Parses the EFI signature database and returns an array of PSCustomObjects
    with proper X.509 certificate parsing instead of ASCII string matching.
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
        # Require enough bytes for the 28-byte signature list header plus a guid
        if ($db.Length - $o -lt 28) { break }
        $guid = [Guid][Byte[]]$db[$o..($o+15)]
        $signatureListSize = [BitConverter]::ToUInt32($db, $o+16)
        $signatureSize = [BitConverter]::ToUInt32($db, $o+24)
        # Guard against malformed firmware: list header is 28 bytes, signatureSize must be nonzero.
        # Without these checks a zero value would cause an infinite loop and hang the script.
        if ($signatureListSize -lt 28 -or $signatureSize -eq 0) { break }
        if ($o + $signatureListSize -gt $db.Length) { break }
        $signatureCount = [Math]::Floor(($signatureListSize - 28) / $signatureSize)
        $so = $o + 28
        for ($i = 0; $i -lt $signatureCount; $i++) {
            $signatureOwner = [Guid][Byte[]]$db[$so..($so+15)]
            if ($guid -eq $EFI_CERT_X509_GUID) {
                # Cert data starts after 16-byte SignatureOwner, length = signatureSize - 16
                $certBytes = $db[($so+16)..($so+$signatureSize-1)]
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
            } elseif ($guid -eq $EFI_CERT_SHA256_GUID -and $signatureSize -ge 48) {
                $sha256Hash = ([Byte[]]$db[($so+16)..($so+47)] | ForEach-Object { $_.ToString('X2') }) -join ''
                $signatures += [PSCustomObject]@{SignatureOwner=$signatureOwner; Signature=$sha256Hash; SignatureType=$guid}
            } else {
                $unknownData = [Byte[]]$db[($so+16)..($so+$signatureSize-1)]
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

# --- STAGED DEPLOYMENT ---
# AvailableUpdates is a bitmask that controls which update steps are triggered:
#   0x04  = KEK update (add KEK 2K CA 2023)
#   0x40  = DB update (add Windows UEFI CA 2023 to Secure Boot DB)
#   0x44  = Phase 1: Add both 2023 certs — SAFEST first step
#   0x100 = Install 2023 Boot Manager (signed by new cert chain)
#   0x200 = SVN update (anti-rollback counter)
#   0x340 = Phase 2: Certs + Boot Manager + SVN
#   0x5944 = Phase 3: Full update including all revocations — most aggressive
#
# Start with Phase 1 (0x44) for new deployments. After confirming certs are
# deployed fleet-wide, increase to 0x340 or 0x5944 for subsequent phases.
# Devices that already have a HIGHER value (e.g. 0x5944 from a previous run)
# will keep their existing value to avoid interrupting an in-progress sequence.
$AvailableUpdatesValue = 0x44
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

# Check if running in a virtual machine -- hypervisors block UEFI variable writes.
# Capture $vmInfo in the same scope as the detection so we don't reference a null $cs later.
$cs = $null
$isVM = $false
$vmInfo = 'unknown'
try {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if ($cs) {
        $isVM = $cs.Model -match 'Virtual Machine|VMware|VirtualBox|Hyper-V|QEMU|Parallels' -or $cs.Manufacturer -match 'VMware|QEMU|Xen|VirtualBox|innotek'
        $vmInfo = "$($cs.Manufacturer) / $($cs.Model)"
    }
} catch {
    $isVM = $false
}

if ($isVM) {
    Write-Output "Virtual machine detected ($vmInfo). Secure Boot variable writes are hypervisor-controlled. This remediation intentionally exits successfully to avoid repeated noise. Exclude VMs or handle via VM-specific process."
    exit 0
}
#endregion

#region ---------------------------------------------------[BitLocker escrow check]----------------------------------------------
# CRITICAL: Modifying Secure Boot DB changes PCR values. If BitLocker is on and the
# recovery key is not escrowed, the user will be locked out with a BitLocker recovery
# screen they cannot pass. This is the #1 bricking scenario reported by the community.
try {
    $blVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
    if ($blVolume -and $blVolume.ProtectionStatus -eq 'On') {
        $recoveryProtectors = $blVolume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
        if (-not $recoveryProtectors) {
            Write-Output "BLOCKED: BitLocker is enabled but no RecoveryPassword protector exists. Cannot safely modify Secure Boot. Add a RecoveryPassword protector and escrow to Entra ID first."
            exit 1
        }

        # Verify recovery key is escrowed — check policy + MDM enrollment as best-effort indicators
        $escrowConfirmed = $false

        # Check if FVE policy requires AD/AAD backup (set by Intune/GPO)
        $aadBackup = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name 'ActiveDirectoryBackup' -ErrorAction SilentlyContinue
        $osAdBackup = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name 'OSActiveDirectoryBackup' -ErrorAction SilentlyContinue
        if (($aadBackup -and $aadBackup.ActiveDirectoryBackup -eq 1) -or ($osAdBackup -and $osAdBackup.OSActiveDirectoryBackup -eq 1)) {
            $escrowConfirmed = $true
        }

        # Fallback: Intune-managed Entra-joined devices escrow keys automatically via MDM policy.
        # Note: Test-Path with a registry wildcard is unreliable in Windows PowerShell 5.1 --
        # enumerate explicitly via Get-ChildItem instead.
        if (-not $escrowConfirmed) {
            $joinInfo = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo\*' -ErrorAction SilentlyContinue
            $mdmEnroll = [bool](Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Enrollments\*\DMClient' -ErrorAction SilentlyContinue)
            if ($joinInfo -and $mdmEnroll) {
                $escrowConfirmed = $true
            }
        }

        # Last resort: attempt to trigger escrow now before proceeding.
        # The cmdlet is BackupToAAD-BitLockerKeyProtector on most Windows builds but may be missing
        # on some newer OS builds -- detect availability before calling to avoid CommandNotFoundException.
        if (-not $escrowConfirmed) {
            try {
                $recoveryId = $recoveryProtectors[0].KeyProtectorId
                $backupCmd = Get-Command BackupToAAD-BitLockerKeyProtector -ErrorAction SilentlyContinue
                if (-not $backupCmd) {
                    Write-Output "BLOCKED: BackupToAAD-BitLockerKeyProtector cmdlet is not available on this OS build. Cannot trigger Entra ID escrow from the script. Verify MDM policy escrows BitLocker keys, then retry."
                    exit 1
                }
                & $backupCmd.Name -MountPoint $env:SystemDrive -KeyProtectorId $recoveryId -ErrorAction Stop
                Write-Output "BitLocker recovery key escrowed to Entra ID successfully."
                $escrowConfirmed = $true
            } catch {
                Write-Output "BLOCKED: BitLocker is enabled but recovery key escrow to Entra ID could not be verified or triggered ($_). Cannot safely modify Secure Boot. Ensure the recovery key is escrowed before retrying."
                exit 1
            }
        }
    }
} catch {
    Write-Output "WARNING: Could not verify BitLocker status: $_. Proceeding with caution."
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
    if ($null -eq $matchedOS) {
        # Unknown build -- do not silently continue; Intune will re-run on a known good build.
        Write-Output "WARNING: OS build '$Build' is not in the known-version table. Proceeding with remediation but patch prerequisite could not be verified."
    } elseif (-not $osPatchOk) {
        Write-Output "OS patch prerequisite not met. Current: $($matchedOS['Name']) $Build.$Patch, Required patch level: $($matchedOS['Patch']). Install the July 2024 cumulative update first."
        exit 1
    }
} catch {
    Write-Output "WARNING: Could not verify OS patch level: $_"
}
#endregion

#region ---------------------------------------------------[Error state check]---------------------------------------------------
try {
    $errVal = Get-ItemProperty -Path $sbServicingPath -Name 'UEFICA2023Error' -ErrorAction SilentlyContinue
    if ($null -ne $errVal -and $null -ne $errVal.UEFICA2023Error -and $errVal.UEFICA2023Error -ne 0) {
        Write-Output "UEFICA2023Error = $($errVal.UEFICA2023Error). Device has a firmware-level failure. Setting registry keys will not fix this. Investigate: check BIOS version, Event Viewer (1795/1796), and contact OEM if needed."
        exit 1
    }
} catch { }
#endregion

#region ---------------------------------------------------[Already-compliant checks]--------------------------------------------
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
        # Use -like with a trailing comma anchor so that "CN=Windows UEFI CA 2023" cannot be falsely
        # matched by a longer CN like "CN=Windows UEFI CA 20230".
        $dbcerts = Get-SecureBootCertSubjects -Database db
        $dbHas2023 = [bool]($dbcerts | Where-Object {
            $_.SignatureSubject -like 'CN=Windows UEFI CA 2023,*' -or
            $_.SignatureSubject -eq   'CN=Windows UEFI CA 2023'
        })

        $KEKcerts = Get-SecureBootCertSubjects -Database kek
        $kekHas2023 = [bool]($KEKcerts | Where-Object {
            $_.SignatureSubject -like 'CN=Microsoft Corporation KEK 2K CA 2023,*' -or
            $_.SignatureSubject -eq   'CN=Microsoft Corporation KEK 2K CA 2023'
        })

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
# Use a non-default name; $errors is a PowerShell automatic variable alias for the error stream.
$remediationErrors = @()

# 1. Set AvailableUpdates (staged deployment).
#    AvailableUpdates is a BITMASK -- a numeric >= comparison is semantically wrong (e.g. 0x100
#    > 0x44 numerically, yet 0x100 lacks the cert bits that 0x44 sets). Instead: OR our target
#    bits onto whatever Windows has already set. If every bit we want is already present, skip
#    the write so we never interrupt an in-progress sequence.
try {
    $av = Get-ItemProperty -Path $sbPath -Name 'AvailableUpdates' -ErrorAction SilentlyContinue
    $currentAvValue = if ($null -ne $av -and $null -ne $av.AvailableUpdates) { $av.AvailableUpdates } else { 0 }
    $targetValue = $currentAvValue -bor $AvailableUpdatesValue
    if ($targetValue -eq $currentAvValue) {
        Write-Output "AvailableUpdates already contains target bits ($('0x{0:X}' -f $currentAvValue) has $('0x{0:X}' -f $AvailableUpdatesValue)) -- no change"
    } else {
        Set-ItemProperty -Path $sbPath -Name 'AvailableUpdates' -Value $targetValue -Type DWord -Force
        if ($currentAvValue -eq 0) {
            Write-Output "Set AvailableUpdates = $('0x{0:X}' -f $targetValue) (Phase 1: cert deployment)"
        } else {
            Write-Output "Merged AvailableUpdates: $('0x{0:X}' -f $currentAvValue) -bor $('0x{0:X}' -f $AvailableUpdatesValue) = $('0x{0:X}' -f $targetValue)"
        }
    }
} catch {
    $remediationErrors += "Failed to set AvailableUpdates: $_"
}

# 2. Set MicrosoftUpdateManagedOptIn to 1 (enroll in Controlled Feature Rollout)
try {
    Set-ItemProperty -Path $sbPath -Name 'MicrosoftUpdateManagedOptIn' -Value 1 -Type DWord -Force
    Write-Output "Set MicrosoftUpdateManagedOptIn = 1"
} catch {
    $remediationErrors += "Failed to set MicrosoftUpdateManagedOptIn: $_"
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
if ($remediationErrors.Count -gt 0) {
    foreach ($e in $remediationErrors) { Write-Output "ERROR: $e" }
    exit 1
}
#endregion

#region ---------------------------------------------------[Start scheduled task]------------------------------------------------
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
