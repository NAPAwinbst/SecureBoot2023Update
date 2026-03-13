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
      "Updated"            - 2023 certs present, fully updated
      "InProgress"         - Update sequence has started but not finished
      "Error"              - Update was attempted but hit an error
      "NotStarted"         - Secure Boot enabled but no update initiated
      "SecureBootDisabled" - Secure Boot is off; cannot apply cert updates
      "VirtualMachine"     - VM; benign not-applicable (aligned with remediation policy)
.NOTES
    Deploy as: Detection script in Intune Remediations
    Run as: System (64-bit)
    Version: 3.3
#>

$result = [ordered]@{
    Hostname              = $env:COMPUTERNAME
    CollectionTime        = (Get-Date -Format 'o')
    SecureBootEnabled     = $false
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
    FirmwareVersion       = $null
    Manufacturer          = $null
    Model                 = $null
    IsVirtualMachine      = $false
    FirmwareCertCheckPerformed = $false
    Status                = 'Unknown'
    Compliant             = $false
}

# --- Device info ---
try {
    $bios = Get-CimInstance Win32_BIOS
    $cs = Get-CimInstance Win32_ComputerSystem
    $os = Get-CimInstance Win32_OperatingSystem
    $result.FirmwareVersion = $bios.SMBIOSBIOSVersion
    $result.Manufacturer = $cs.Manufacturer
    $result.Model = $cs.Model
    $result.OSVersion = $os.Version
    $result.IsVirtualMachine = ($cs.Model -match 'Virtual Machine' -or $cs.Manufacturer -match 'VMware|QEMU|Xen|VirtualBox|innotek')
} catch { }

# --- VM = benign not-applicable (exit before Secure Boot to avoid false SecureBootDisabled) ---
if ($result.IsVirtualMachine) {
    $result.Status = 'VirtualMachine'
    $result.Compliant = $true
    Write-Output ($result | ConvertTo-Json -Compress)
    exit 0
}

# --- Check Secure Boot state ---
try {
    $result.SecureBootEnabled = Confirm-SecureBootUEFI
} catch {
    $result.SecureBootEnabled = $false
}

if (-not $result.SecureBootEnabled) {
    $result.Status = 'SecureBootDisabled'
    $result.Compliant = $false
    Write-Output ($result | ConvertTo-Json -Compress)
    exit 1
}

# --- Read registry keys ---
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
        # Value is a Windows FILETIME (100-nanosecond intervals since 1601-01-01) -- convert to ISO 8601
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

# --- Check event logs (last 30 days only -- unbounded queries can timeout on large logs) ---
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

# --- Determine compliance (ordered for signal quality & alignment with remediation) ---

# Firmware/servicing error state should always be surfaced for investigation
if ($null -ne $result.UEFICA2023Error -and $result.UEFICA2023Error -ne 0) {
    $result.Status = 'Error'
    $result.Compliant = $false
    Write-Output ($result | ConvertTo-Json -Compress)
    exit 1
}

# Servicing status is the authoritative tracking signal (Microsoft's intended monitoring key)
if ($result.UEFICA2023Status -eq 'Updated') {
    $result.Status = 'Updated'
    $result.Compliant = $true
    Write-Output ($result | ConvertTo-Json -Compress)
    exit 0
}

# In progress: servicing status indicates update sequence has started
# Some builds may represent this differently; we defensively handle both string and integer
if ($result.UEFICA2023Status -eq 'InProgress' -or $result.UEFICA2023Status -eq 1) {
    $result.Status = 'InProgress'
    $result.Compliant = $false
    Write-Output ($result | ConvertTo-Json -Compress)
    exit 1
}

# Fallback: if servicing status is absent, attempt best-effort firmware certificate check.
# Only read UEFI DB/KEK when we actually need them -- avoids unnecessary UEFI reads and
# noisy false negatives in JSON fields when servicing keys already gave a definitive answer.
if ([string]::IsNullOrWhiteSpace($result.UEFICA2023Status) -or $result.UEFICA2023Status -eq 'NotStarted') {
    $result.FirmwareCertCheckPerformed = $true
    try {
        $db = Get-SecureBootUEFI -Name db
        $dbString = [System.Text.Encoding]::ASCII.GetString($db.Bytes)
        $result.Cert2023InDB = ($dbString -match 'Windows UEFI CA 2023')
    } catch {
        $result.Cert2023InDB = $false
    }

    try {
        $kek = Get-SecureBootUEFI -Name kek
        $kekString = [System.Text.Encoding]::ASCII.GetString($kek.Bytes)
        $result.KEK2023Present = ($kekString -match 'Microsoft Corporation KEK 2K CA 2023')
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
