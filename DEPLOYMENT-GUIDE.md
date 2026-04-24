# Secure Boot 2023 Certificate Update — Intune Remediation Deployment Guide

## What's included

| File | Purpose |
|------|---------|
| `Detect-SecureBootCertUpdate.ps1` | Detection script — checks compliance and outputs JSON status |
| `Remediate-SecureBootCertUpdate.ps1` | Remediation script — sets registry keys to trigger the update |

## How it works

**Detection** checks:
- Is Secure Boot enabled? (if not → non-compliant, flagged)
- Is "Windows UEFI CA 2023" present in the Secure Boot DB AND "Microsoft Corporation KEK 2K CA 2023" in KEK? → **exit 0 (compliant)**
- Otherwise collects full registry and event log status and → **exit 1 (non-compliant)**, triggering remediation

**Remediation** sets:
- `AvailableUpdates` — triggers certificate deployment. **Staged by phase** (see below). The value is OR-merged onto whatever Windows already has so existing bits are never cleared.
- `MicrosoftUpdateManagedOptIn` = `1` — enrolls in Microsoft's Controlled Feature Rollout
- `HighConfidenceOptOut` = `0` — ensures automatic monthly updates aren't blocked

The remediation skips devices that are already updated to avoid unnecessary work.

### Staged deployment of `AvailableUpdates`

The script's `$AvailableUpdatesValue` variable controls which phase is applied. Default is **Phase 1**. Advance phases manually once the fleet is stable at the previous phase.

| Phase | Value | Bits | What it triggers |
|-------|-------|------|------------------|
| 1 (default, safest) | `0x44` | KEK + DB | Add Windows UEFI CA 2023 to the DB and KEK 2K CA 2023 to the KEK |
| 2 (intermediate) | `0x340` | Phase 1 + `0x100` Boot Manager + `0x200` SVN | Install the 2023-signed boot manager and advance the anti-rollback counter |
| 3 (full rollout) | `0x5944` | Phase 2 + revocations | Complete update including revocations of the 2011 cert chain |

Edit `$AvailableUpdatesValue` in `Remediate-SecureBootCertUpdate.ps1` to advance. Devices that already have higher bits set will keep them — the script only adds the missing ones.

> **Alternative:** Microsoft's Intune Settings Catalog (Devices > Configuration > Settings Catalog > search "Secure Boot") can deploy these same three registry values natively without a custom remediation script. Use this package for detection/reporting regardless — it gives you the detailed JSON status per device that Settings Catalog alone cannot provide.

## Deploy in Intune

1. Go to **Devices > Scripts and Remediations > + Create script package**
2. **Basics tab:**
   - Name: `Secure Boot 2023 Certificate Update`
   - Description: `Deploys 2023 Secure Boot certificates via registry keys and monitors update progress fleet-wide.`
3. **Settings tab:**
   - Detection script: upload `Detect-SecureBootCertUpdate.ps1`
   - Remediation script: upload `Remediate-SecureBootCertUpdate.ps1`
   - Run this script using the logged-on credentials: **No** (run as System)
   - Enforce script signature check: **No** (unless you sign them)
   - Run script in 64-bit PowerShell: **Yes** ← Important!
4. **Assignments tab:**
   - Start with a pilot group, then expand to all Windows devices
5. **Schedule:**
   - Recommended: **Once daily** during rollout, then drop to every 3 days once stable

## Prerequisites

Before deploying, ensure:

- [ ] **Windows Diagnostic Data** is set to at least Required/Basic via Intune Settings Catalog
- [ ] **BitLocker recovery keys** are escrowed in Entra ID for all target devices
- [ ] **OEM firmware updates** have been applied where available
- [ ] **Pilot group** is defined with representative hardware from your fleet
- [ ] **Virtual machines are excluded** from the assignment — Hyper-V, VMware, and other hypervisors block UEFI variable writes

## Monitoring progress

### In Intune
Go to **Devices > Scripts and Remediations** > select your package > **Device status**.

Add the column **Pre-remediation detection output** to see the JSON status per device.

### Key fields in the JSON output

| Field | What to look for |
|-------|-----------------|
| `SecureBootEnabled` | `false` = Secure Boot off, device flagged non-compliant |
| `Cert2023InDB` | `true` = new cert is in firmware DB |
| `KEK2023Present` | `true` = new KEK is enrolled |
| `UEFICA2023Status` | `"Updated"` = fully complete, `"InProgress"` = working, `"NotStarted"` = not yet attempted |
| `UEFICA2023Error` | Should be `null` or `0` — any non-zero value means a failure occurred |
| `UEFICA2023ErrorEvent` | Companion to `UEFICA2023Error` — records the specific event code from the failure |
| `CanAttemptUpdateAfter` | If set, Microsoft is throttling this device until that date — nothing will happen until then |
| `WindowsUEFICA2023Capable` | `0` = Microsoft hasn't cleared this device for the update yet (CFR). `1` = cleared and ready |
| `ConfidenceLevel` | Microsoft's CFR confidence assessment — explains why `WindowsUEFICA2023Capable` may be 0 |
| `AvailableUpdates` | `0x44` → Phase 1 triggered. `0x340` → Phase 2 triggered. `0x5944` → Phase 3 triggered. `0x400` → Windows-managed default. `0x4104` → OEM KEK not yet signed (emits 1803, will retry). `0x4100` → reboot needed. `0x4000` → nearly done. `0x0` → complete |
| `Event1808Count` | > 0 = certificates successfully applied |
| `Event1801Count` | > 0 = certificates available but not yet applied (pending or stuck) |
| `Event1795Count` | > 0 = firmware error when writing certs to UEFI variables — check OEM BIOS update |
| `Event1796Count` | > 0 = KEK update specifically failed — OEM may need to sign the new KEK |
| `IsVirtualMachine` | `true` = VM detected; cert writes are blocked by hypervisor, exclude from this remediation |
| `MicrosoftUpdateOptIn` | `1` = enrolled in CFR |
| `HighConfidenceOptOut` | `0` or null = not blocking automatic updates |

### Export and analyze
1. In the Remediation device status view, click **Export**
2. Open the CSV in Excel
3. The `PreRemediationDetectionScriptOutput` column contains the JSON
4. Use Excel's Power Query or a script to parse the JSON into columns

### PowerShell quick parse for exported CSV
```powershell
$csv = Import-Csv ".\RemediationExport.csv"
$csv | ForEach-Object {
    $json = $_.PreRemediationDetectionScriptOutput | ConvertFrom-Json
    [PSCustomObject]@{
        Device                   = $json.Hostname
        Status                   = $json.Status
        Compliant                = $json.Compliant
        SecureBoot               = $json.SecureBootEnabled
        Cert2023InDB             = $json.Cert2023InDB
        KEK2023Present           = $json.KEK2023Present
        UEFICA2023Status         = $json.UEFICA2023Status
        UEFICA2023Error          = $json.UEFICA2023Error
        UEFICA2023ErrorEvent     = $json.UEFICA2023ErrorEvent
        WindowsUEFICA2023Capable = $json.WindowsUEFICA2023Capable
        CanAttemptAfter          = $json.CanAttemptUpdateAfter
        ConfidenceLevel          = $json.ConfidenceLevel
        AvailableUpdates         = $json.AvailableUpdates
        OptIn                    = $json.MicrosoftUpdateOptIn
        Event1808                = $json.Event1808Count
        Event1801                = $json.Event1801Count
        Event1795                = $json.Event1795Count
        Event1796                = $json.Event1796Count
        IsVM                     = $json.IsVirtualMachine
        Manufacturer             = $json.Manufacturer
        Model                    = $json.Model
        FirmwareVersion          = $json.FirmwareVersion
        OSVersion                = $json.OSVersion
    }
} | Export-Csv ".\SecureBootStatus.csv" -NoTypeInformation
```

## Troubleshooting

| Symptom | Cause | Action |
|---------|-------|--------|
| `AvailableUpdates` stuck at the configured phase value (e.g. `0x44`, `0x340`, or `0x5944`) | Scheduled task hasn't run yet | Wait 12 hours or manually run `Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"` |
| `AvailableUpdates` stuck at `0x4104` | OEM hasn't signed the 2023 KEK with their Platform Key | Windows will keep retrying (Event 1803 each attempt). Contact OEM for firmware update. |
| `AvailableUpdates` stuck at `0x4100` | Needs a reboot to continue | Reboot the device |
| `UEFICA2023Error` has a non-zero value | A specific update step failed | Check `UEFICA2023ErrorEvent` for the event code, then look in Event Viewer System log |
| `Event1795Count` > 0 | Firmware rejected the certificate write | Check OEM for a BIOS update. Device firmware cannot accept the cert at this version. |
| `Event1796Count` > 0 | KEK update specifically failed | OEM may not have signed the new KEK with their Platform Key. Contact OEM. |
| `Event1801Count` > 0, no 1795/1796 | Certs available but not yet applied | Check `CanAttemptUpdateAfter` — device may be throttled by Microsoft CFR. Also check `WindowsUEFICA2023Capable` in the Servicing registry key. |
| `IsVirtualMachine` is `true` | Hypervisor blocks UEFI variable writes | Exclude VMs from this remediation assignment. Apply certs via host BIOS or different mechanism. |
| Device triggers BitLocker recovery | Secure Boot variable change detected | Use escrowed recovery key. This is why key backup is a prerequisite. |
| `Cert2023InDB` stays `false` after 48h | Device isn't processing updates | Verify internet access, the scheduled task exists, and `CanAttemptUpdateAfter` isn't blocking it |

## Timeline

After remediation runs on a device, expect:
1. **Next scheduled task run**: The `Secure-Boot-Update` task picks up `AvailableUpdates` and begins processing
2. **First reboot**: Certificates written to firmware, boot manager staged
3. **Second reboot** (may happen naturally): Boot manager updated
4. **12 hours after final reboot**: Status should show `Updated`

Allow **48 hours and at least 2 restarts** before investigating non-progressing devices.
