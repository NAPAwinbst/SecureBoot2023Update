<#
.SYNOPSIS
    Intune Remediation Detection Script - Secure Boot 2023 Certificate Update
.DESCRIPTION
    Checks whether the device needs Secure Boot certificate updates.
    Exit 0 = Compliant (no action needed)
    Exit 1 = Non-Compliant (remediation needed or attention required)

    The pre-remediation detection output is a JSON string with detailed
    device status for reporting in the Intune admin center.

    Status values:
      "Updated"             - 2023 certs present, fully updated
      "InProgress"          - Update sequence has started but not finished
      "Error"               - Update was attempted but hit an error
      "NotStarted"          - Secure Boot enabled but no update initiated
      "SecureBootDisabled"  - Secure Boot is off; cannot apply cert updates
      "VirtualMachine"      - VM; benign not-applicable (aligned with remediation policy)
      "PrerequisitesNotMet" - Script not running as 64-bit or elevated
      "OSPatchMissing"      - Required July 2024 cumulative update not installed
      "BitLockerNotEscrowed"- BitLocker is on but recovery key not safely escrowed
.NOTES
    Deploy as: Detection script in Intune Remediations
    Run as: System (64-bit)
    Version: 5.2
    Based on original work by @MrTbone_se (T-bone Granheden) - MIT License
#>

#region ---------------------------------------------------[Functions]------------------------------------------------------------
# IMPORTANT: This function is duplicated in the Remediation script - keep both in sync.
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
#endregion

#region ---------------------------------------------------[Initialize result object]--------------------------------------------
$result = [ordered]@{
    Hostname              = $env:COMPUTERNAME
    CollectionTime        = (Get-Date).ToUniversalTime().ToString('o')
    SecureBootEnabled     = $null
    Cert2023InDB          = $false
    KEK2023Present        = $false
    UEFICA2023Status      = $null
    UEFICA2023Error       = $null
    CanAttemptUpdateAfter = $null
    AvailableUpdates      = $null
    MicrosoftUpdateOptIn  = $null
    HighConfidenceOptOut  = $null
    UEFICA2023ErrorEvent        = $null
    ConfidenceLevel             = $null
    WindowsUEFICA2023Capable    = $null
    Event1808Count        = 0
    Event1801Count        = 0
    Event1795Count        = 0
    Event1796Count        = 0
    OSVersion             = $null
    OSName                = $null
    OSPatchCompliant      = $null
    FirmwareType          = $null
    FirmwareVersion       = $null
    FirmwareDate          = $null
    Manufacturer          = $null
    Model                 = $null
    IsVirtualMachine      = $false
    BitLockerEnabled      = $null
    BitLockerEncryptionMethod = $null
    BitLockerKeyProtectors    = $null
    BitLockerRecoveryEscrowed = $null
    TPMPresent            = $null
    TPMEnabled            = $null
    TPMVersion            = $null
    TPMEventStatus        = $null
    DiskPartitionStyle    = $null
    SecureBootPK          = $null
    SecureBootKEK         = $null
    SecureBootDB          = $null
    FirmwareCertCheckPerformed = $false
    Status                = 'Unknown'
    Compliant             = $false
}
#endregion

#region ---------------------------------------------------[Device info]---------------------------------------------------------
# Collect device info FIRST so it's always in the JSON output, even if prerequisites fail
try {
    $bios = Get-CimInstance Win32_BIOS -Property SMBIOSBIOSVersion,ReleaseDate -ErrorAction SilentlyContinue
    $cs = Get-CimInstance Win32_ComputerSystem -Property Manufacturer,Model -ErrorAction SilentlyContinue
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $result.FirmwareVersion = $bios.SMBIOSBIOSVersion
    $result.FirmwareDate = if ($bios -and $bios.ReleaseDate) { $bios.ReleaseDate.ToString("yyyy-MM-dd") } else { "Unknown" }
    $result.Manufacturer = $cs.Manufacturer
    $result.Model = $cs.Model
    $result.OSVersion = $os.Version
    $result.IsVirtualMachine = ($cs.Model -match 'Virtual Machine|VMware|VirtualBox|Hyper-V|QEMU|Parallels' -or $cs.Manufacturer -match 'VMware|QEMU|Xen|VirtualBox|innotek')
} catch { }

# Firmware type (BIOS vs UEFI) -- use registry method to avoid bcdedit localization issues
try {
    $peFirmwareType = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control' -Name 'PEFirmwareType' -ErrorAction SilentlyContinue).PEFirmwareType
    $result.FirmwareType = if ($peFirmwareType -eq 2) { "UEFI" } elseif ($peFirmwareType -eq 1) { "BIOS" } else { "Unknown" }
} catch { $result.FirmwareType = "Unknown" }

# TPM diagnostics
try {
    $tpmWmi = Get-CimInstance -Namespace "Root\CIMv2\Security\MicrosoftTpm" -ClassName Win32_Tpm -ErrorAction SilentlyContinue
    $result.TPMPresent = if ($tpmWmi) { $true } else { $false }
    $result.TPMEnabled = if ($tpmWmi) { $tpmWmi.IsEnabled_InitialValue } else { $null }
    $result.TPMVersion = if ($tpmWmi -and $tpmWmi.SpecVersion) { $tpmWmi.SpecVersion.Split(",")[0].Trim() } else { $null }
} catch { }

# TPM event log status (1808=success, 1801=failure)
try {
    $TPMevent = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-TPM-WMI'; Id=@(1808,1801)} -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($TPMevent) {
        $shortMsg = ($TPMevent.Message -replace '\s+',' ') -replace '(.{200}).+','$1...'
        $result.TPMEventStatus = "$($TPMevent.Id) - $($TPMevent.TimeCreated.ToString('s')) - $shortMsg"
    } else { $result.TPMEventStatus = "No logs" }
} catch { }

# Disk partition style
try {
    $osdisk = Get-Disk -ErrorAction SilentlyContinue | Where-Object { $_.IsBoot -eq $true } | Select-Object -First 1
    $result.DiskPartitionStyle = if ($osDisk) { $osDisk.PartitionStyle } else { "Unknown" }
} catch { $result.DiskPartitionStyle = "Unknown" }
#endregion

#region ---------------------------------------------------[Prerequisites check]-------------------------------------------------
# Validate 64-bit PowerShell
if ([IntPtr]::Size -ne 8) {
    $result.Status = 'PrerequisitesNotMet'
    $result.Compliant = $false
    Write-Output ($result | ConvertTo-Json -Compress)
    exit 1
}

# Validate elevated privileges (SYSTEM or Administrator)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isElevated = $identity.User.Value -eq "S-1-5-18" -or ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isElevated) {
    $result.Status = 'PrerequisitesNotMet'
    $result.Compliant = $false
    Write-Output ($result | ConvertTo-Json -Compress)
    exit 1
}
#endregion

#region ---------------------------------------------------[BitLocker status]----------------------------------------------------
# Secure Boot DB changes alter PCR values that BitLocker validates at boot.
# If recovery key is not escrowed, the user gets a BitLocker recovery screen they cannot pass.
try {
    $blVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
    if ($blVolume -and $blVolume.ProtectionStatus -eq 'On') {
        $result.BitLockerEnabled = $true
        $result.BitLockerEncryptionMethod = $blVolume.EncryptionMethod.ToString()
        $result.BitLockerKeyProtectors = ($blVolume.KeyProtector | ForEach-Object { $_.KeyProtectorType.ToString() }) -join '; '
        # Check if a RecoveryPassword protector exists (required for escrow to Entra ID)
        $recoveryProtectors = $blVolume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
        if ($recoveryProtectors) {
            # Check if recovery key has been backed up to AAD/Entra ID
            # The FVE metadata in WMI tracks backup status
            # Check if FVE policy requires AD/AAD backup (set by Intune/GPO)
            $aadBackup = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name 'ActiveDirectoryBackup' -ErrorAction SilentlyContinue
            $osAdBackup = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name 'OSActiveDirectoryBackup' -ErrorAction SilentlyContinue
            if (($aadBackup -and $aadBackup.ActiveDirectoryBackup -eq 1) -or ($osAdBackup -and $osAdBackup.OSActiveDirectoryBackup -eq 1)) {
                $result.BitLockerRecoveryEscrowed = $true
            } else {
                # Fallback: Intune-managed Entra-joined devices escrow keys automatically via MDM policy.
                # Note: Test-Path with a registry wildcard is unreliable in Windows PowerShell 5.1 --
                # enumerate explicitly via Get-ChildItem instead.
                $joinInfo = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo\*' -ErrorAction SilentlyContinue
                $mdmEnroll = [bool](Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Enrollments\*\DMClient' -ErrorAction SilentlyContinue)
                if ($joinInfo -and $mdmEnroll) {
                    $result.BitLockerRecoveryEscrowed = $true
                } else {
                    $result.BitLockerRecoveryEscrowed = $false
                }
            }
        } else {
            # BitLocker is on but no RecoveryPassword protector exists — cannot escrow
            $result.BitLockerRecoveryEscrowed = $false
        }
    } else {
        $result.BitLockerEnabled = $false
        $result.BitLockerRecoveryEscrowed = $null  # N/A — not encrypted
    }
} catch {
    # BitLocker module not available or query failed
    $result.BitLockerEnabled = $null
    $result.BitLockerRecoveryEscrowed = $null
}
#endregion

#region ---------------------------------------------------[OS patch prerequisite check]-----------------------------------------
try {
    $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
    $Build = if ($cv.CurrentBuildNumber) { try {[int]$cv.CurrentBuildNumber} catch { $null } } elseif ($cv.CurrentBuild) { try {[int]$cv.CurrentBuild} catch { $null } } else { $null }
    $Patch = if ($null -ne $cv.UBR) { try {[int]$cv.UBR} catch { $null } } else { $null }
    $OSversionsSorted = $OSversions | Sort-Object { [int]$_.Build } -Descending
    $matchedOS = $OSversionsSorted | Where-Object { ($Build -ne $null) -and ([int]$_.Build -le $Build) } | Select-Object -First 1
    if ($matchedOS) {
        $result.OSName = "$($matchedOS['Name']) ($Build$(if($null -ne $Patch){".$Patch"}))"
        if ($matchedOS['Patch'] -eq 0) { $result.OSPatchCompliant = $true }
        elseif ($null -ne $Patch -and $Patch -ge $matchedOS['Patch']) { $result.OSPatchCompliant = $true }
        else { $result.OSPatchCompliant = $false }
    } else {
        $result.OSName = "Unknown ($Build$(if($null -ne $Patch){".$Patch"}))"
        $result.OSPatchCompliant = $null
    }
} catch { }
#endregion

#region ---------------------------------------------------[VM early exit]-------------------------------------------------------
if ($result.IsVirtualMachine) {
    $result.Status = 'VirtualMachine'
    $result.Compliant = $true
    Write-Output ($result | ConvertTo-Json -Compress)
    exit 0
}
#endregion

#region ---------------------------------------------------[Check Secure Boot state]---------------------------------------------
try {
    $result.SecureBootEnabled = Confirm-SecureBootUEFI
} catch {
    $result.SecureBootEnabled = $false
}

if (-not $result.SecureBootEnabled) {
    # Not remediable by script: Secure Boot must be enabled in firmware/BIOS by a user/admin.
    # exit 0 so Intune does not loop remediation endlessly; Compliant=false still surfaces the issue in reports.
    $result.Status = 'SecureBootDisabled'
    $result.Compliant = $false
    Write-Output ($result | ConvertTo-Json -Compress)
    exit 0
}
#endregion

#region ---------------------------------------------------[Read registry keys]--------------------------------------------------
$sbPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot'
$sbServicingPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing'
$sbDeviceAttributesPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\DeviceAttributes'

try {
    $av = Get-ItemProperty -Path $sbPath -Name 'AvailableUpdates' -ErrorAction SilentlyContinue
    if ($null -ne $av.AvailableUpdates) { $result.AvailableUpdates = '0x{0:X}' -f $av.AvailableUpdates }
} catch { }

try {
    $optIn = Get-ItemProperty -Path $sbPath -Name 'MicrosoftUpdateManagedOptIn' -ErrorAction SilentlyContinue
    if ($null -ne $optIn.MicrosoftUpdateManagedOptIn) { $result.MicrosoftUpdateOptIn = $optIn.MicrosoftUpdateManagedOptIn }
} catch { }

try {
    $optOut = Get-ItemProperty -Path $sbPath -Name 'HighConfidenceOptOut' -ErrorAction SilentlyContinue
    if ($null -ne $optOut.HighConfidenceOptOut) { $result.HighConfidenceOptOut = $optOut.HighConfidenceOptOut }
} catch { }

try {
    $status = Get-ItemProperty -Path $sbServicingPath -Name 'UEFICA2023Status' -ErrorAction SilentlyContinue
    if ($null -ne $status.UEFICA2023Status) { $result.UEFICA2023Status = $status.UEFICA2023Status }
} catch { }

try {
    $err = Get-ItemProperty -Path $sbServicingPath -Name 'UEFICA2023Error' -ErrorAction SilentlyContinue
    if ($null -ne $err.UEFICA2023Error) { $result.UEFICA2023Error = $err.UEFICA2023Error }
} catch { }

try {
    # CanAttemptUpdateAfter path varies by Windows version -- try both locations
    $throttle = Get-ItemProperty -Path $sbDeviceAttributesPath -Name 'CanAttemptUpdateAfter' -ErrorAction SilentlyContinue
    if ($null -eq $throttle) {
        $throttle = Get-ItemProperty -Path "$sbServicingPath\DeviceAttributes" -Name 'CanAttemptUpdateAfter' -ErrorAction SilentlyContinue
    }
    if ($null -ne $throttle.CanAttemptUpdateAfter -and $throttle.CanAttemptUpdateAfter -ne 0) {
        $result.CanAttemptUpdateAfter = [DateTime]::FromFileTimeUtc($throttle.CanAttemptUpdateAfter).ToString('o')
    }
} catch { }

try {
    $errEvent = Get-ItemProperty -Path $sbServicingPath -Name 'UEFICA2023ErrorEvent' -ErrorAction SilentlyContinue
    if ($null -ne $errEvent.UEFICA2023ErrorEvent) { $result.UEFICA2023ErrorEvent = $errEvent.UEFICA2023ErrorEvent }
} catch { }

try {
    $cl = Get-ItemProperty -Path $sbServicingPath -Name 'ConfidenceLevel' -ErrorAction SilentlyContinue
    if ($null -ne $cl.ConfidenceLevel) { $result.ConfidenceLevel = $cl.ConfidenceLevel }
} catch { }

try {
    $capable = Get-ItemProperty -Path $sbServicingPath -Name 'WindowsUEFICA2023Capable' -ErrorAction SilentlyContinue
    if ($null -ne $capable.WindowsUEFICA2023Capable) { $result.WindowsUEFICA2023Capable = $capable.WindowsUEFICA2023Capable }
} catch { }
#endregion

#region ---------------------------------------------------[Check event logs]----------------------------------------------------
# Last 30 days only -- unbounded queries can timeout on large logs
$eventCutoff = (Get-Date).AddDays(-30)

try {
    $result.Event1808Count = @(Get-WinEvent -FilterHashtable @{LogName='System'; Id=1808; StartTime=$eventCutoff} -ErrorAction SilentlyContinue).Count
} catch { }

try {
    $result.Event1801Count = @(Get-WinEvent -FilterHashtable @{LogName='System'; Id=1801; StartTime=$eventCutoff} -ErrorAction SilentlyContinue).Count
} catch { }

try {
    $result.Event1795Count = @(Get-WinEvent -FilterHashtable @{LogName='System'; Id=1795; StartTime=$eventCutoff} -ErrorAction SilentlyContinue).Count
} catch { }

try {
    $result.Event1796Count = @(Get-WinEvent -FilterHashtable @{LogName='System'; Id=1796; StartTime=$eventCutoff} -ErrorAction SilentlyContinue).Count
} catch { }
#endregion

#region ---------------------------------------------------[Determine compliance]------------------------------------------------

# Check "Updated" first: a device that eventually succeeded can have a stale non-zero error code
# left over from an earlier failed attempt. Checking Error before Updated would falsely flag those
# devices non-compliant forever and cause Intune to loop remediation on a done device.
if ($result.UEFICA2023Status -eq 'Updated') {
    $result.Status = 'Updated'
    $result.Compliant = $true
    Write-Output ($result | ConvertTo-Json -Compress)
    exit 0
}

# Firmware/servicing error state (only when not already Updated) should be surfaced for investigation
if ($null -ne $result.UEFICA2023Error -and $result.UEFICA2023Error -ne 0) {
    $result.Status = 'Error'
    $result.Compliant = $false
    Write-Output ($result | ConvertTo-Json -Compress)
    exit 1
}

# OS patch prerequisite check -- device cannot complete update without the July 2024 KB
# Note: exit 0 with Compliant=$false so Intune does not trigger remediation (remediation cannot install OS patches)
if ($result.OSPatchCompliant -eq $false) {
    $result.Status = 'OSPatchMissing'
    $result.Compliant = $false
    Write-Output ($result | ConvertTo-Json -Compress)
    exit 0
}

# BitLocker escrow check -- if BitLocker is on but recovery key is not escrowed, do not trigger remediation
# Modifying Secure Boot without escrowed keys causes BitLocker recovery lockout
if ($result.BitLockerEnabled -eq $true -and $result.BitLockerRecoveryEscrowed -eq $false) {
    $result.Status = 'BitLockerNotEscrowed'
    $result.Compliant = $false
    Write-Output ($result | ConvertTo-Json -Compress)
    exit 0
}

# In progress: servicing status indicates update sequence has started.
# exit 0 here to avoid re-triggering remediation (and the scheduled task) while an update is mid-flight.
# Some builds may represent this differently; defensively handle both string and integer.
if ($result.UEFICA2023Status -eq 'InProgress' -or $result.UEFICA2023Status -eq 1) {
    $result.Status = 'InProgress'
    $result.Compliant = $false
    Write-Output ($result | ConvertTo-Json -Compress)
    exit 0
}

#endregion

#region ---------------------------------------------------[Cert diagnostics + fallback]-----------------------------------------
# Collect Secure Boot cert subjects using proper X.509 parsing.
# Deferred to here so compliant devices (Updated exit above) skip the expensive UEFI reads.
try {
    $PKcerts = Get-SecureBootCertSubjects -Database pk
    if ($PKcerts) {
        $pkSubjects = ($PKcerts | ForEach-Object { if ($_.SignatureSubject -match 'CN=(.+?),') { $matches[1] } else { $_.SignatureSubject } }) -join '; '
        if ($pkSubjects.Length -gt 500) { $pkSubjects = $pkSubjects.Substring(0,497) + '...' }
        $result.SecureBootPK = $pkSubjects
    }
} catch { }

try {
    $KEKcerts = Get-SecureBootCertSubjects -Database kek
    if ($KEKcerts) {
        $kekSubjects = ($KEKcerts | ForEach-Object { if ($_.SignatureSubject -match 'CN=(.+?),') { $matches[1] } else { $_.SignatureSubject } }) -join '; '
        if ($kekSubjects.Length -gt 500) { $kekSubjects = $kekSubjects.Substring(0,497) + '...' }
        $result.SecureBootKEK = $kekSubjects
    }
} catch { }

try {
    $dbcerts = Get-SecureBootCertSubjects -Database db
    if ($dbcerts) {
        $dbSubjects = ($dbcerts | ForEach-Object { if ($_.SignatureSubject -match 'CN=(.+?),') { $matches[1] } else { $_.SignatureSubject } }) -join '; '
        if ($dbSubjects.Length -gt 500) { $dbSubjects = $dbSubjects.Substring(0,497) + '...' }
        $result.SecureBootDB = $dbSubjects
    }
} catch { }

# Fallback compliance check: if servicing status is absent or NotStarted, use parsed certs
if ([string]::IsNullOrWhiteSpace($result.UEFICA2023Status) -or $result.UEFICA2023Status -eq 'NotStarted') {
    $result.FirmwareCertCheckPerformed = $true
    # Use -like with a trailing comma anchor so that "CN=Windows UEFI CA 2023" cannot be falsely
    # matched by a longer CN like "CN=Windows UEFI CA 20230". Cert subjects look like
    # "CN=Windows UEFI CA 2023, O=Microsoft Corporation, L=Redmond, S=Washington, C=US".
    try {
        if ($dbcerts) {
            $result.Cert2023InDB = [bool]($dbcerts | Where-Object {
                $_.SignatureSubject -like 'CN=Windows UEFI CA 2023,*' -or
                $_.SignatureSubject -eq   'CN=Windows UEFI CA 2023'
            })
        }
    } catch {
        $result.Cert2023InDB = $false
    }

    try {
        if ($KEKcerts) {
            $result.KEK2023Present = [bool]($KEKcerts | Where-Object {
                $_.SignatureSubject -like 'CN=Microsoft Corporation KEK 2K CA 2023,*' -or
                $_.SignatureSubject -eq   'CN=Microsoft Corporation KEK 2K CA 2023'
            })
        }
    } catch {
        $result.KEK2023Present = $false
    }

    # Both 2023 certs present in firmware (e.g. BIOS pre-installed them)
    if ($result.Cert2023InDB -and $result.KEK2023Present) {
        $result.Status = 'Updated'
        $result.Compliant = $true
        Write-Output ($result | ConvertTo-Json -Compress)
        exit 0
    }

    # Partial progress heuristic: DB has 2023 cert but KEK still missing
    if ($result.Cert2023InDB -and (-not $result.KEK2023Present)) {
        $result.Status = 'InProgress'
        $result.Compliant = $false
        Write-Output ($result | ConvertTo-Json -Compress)
        exit 1
    }
}

# Not started: Secure Boot is on but no success signals detected
$result.Status = 'NotStarted'
$result.Compliant = $false
Write-Output ($result | ConvertTo-Json -Compress)
exit 1
#endregion
