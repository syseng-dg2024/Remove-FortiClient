#Requires -RunAsAdministrator

$ErrorActionPreference = 'Continue'
$fortiClientLogDirectory = 'C:\temp\FortiClientRemoval'
$registryBackupDirectory = Join-Path $fortiClientLogDirectory 'backup'
New-Item -ItemType Directory -Path $registryBackupDirectory -Force | Out-Null
$removalLogFilePath = Join-Path $fortiClientLogDirectory ("removal_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
$script:IsDryRunPass = $true

function Write-RemovalLog {
    param([string]$Message)
    $logLine = "[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Write-Host $logLine
    Add-Content -Path $removalLogFilePath -Value $logLine
}

# Converts PowerShell registry paths to native paths, e.g. HKEY_LOCAL_MACHINE\SOFTWARE\...
function ConvertTo-NativeRegistryPath {
    param([string]$RegistryPathInput)
    $nativePath = $RegistryPathInput -replace '^Microsoft\.PowerShell\.Core\\', ''
    $nativePath = $nativePath -replace '^Registry::', ''
    $nativePath = $nativePath -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\'
    $nativePath = $nativePath -replace '^HKU\\', 'HKEY_USERS\'
    return $nativePath
}

# Only these key shapes may ever be deleted. Anything else is refused.
$allowedNativeRemovalPatterns = @(
    '^HKEY_USERS\\[^\\]+\\Software\\Fortinet$',
    '^HKEY_USERS\\[^\\]+\\Software\\Microsoft\\Installer\\Products\\[^\\]+$',
    '^HKEY_USERS\\[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\[^\\]+$',
    '^HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Installer\\Products\\[^\\]+$',
    '^HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Installer\\UserData\\[^\\]+\\Products\\[^\\]+$',
    '^HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\[^\\]+$',
    '^HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\[^\\]+$'
)

function Test-IsAllowedRemovalPath {
    param([string]$NativePath)
    foreach ($allowedPattern in $allowedNativeRemovalPatterns) {
        if ($NativePath -match $allowedPattern) { return $true }
    }
    return $false
}

# Exports one key to the backup folder. Returns $true only if the .reg file was written.
$script:backupExportCounter = 0
function Export-RegistryKeyBackup {
    param([string]$NativePath)
    $script:backupExportCounter++
    $regExeKeyPath    = $NativePath -replace '^HKEY_USERS', 'HKU' -replace '^HKEY_LOCAL_MACHINE', 'HKLM'
    $sanitizedKeyName = $NativePath -replace '[^A-Za-z0-9]', '_'
    if ($sanitizedKeyName.Length -gt 120) { $sanitizedKeyName = $sanitizedKeyName.Substring(0, 120) }
    $backupFilePath = Join-Path $registryBackupDirectory ("{0:D3}_{1}.reg" -f $script:backupExportCounter, $sanitizedKeyName)
    reg.exe export $regExeKeyPath $backupFilePath /y | Out-Null
    return (($LASTEXITCODE -eq 0) -and (Test-Path $backupFilePath))
}

# Backs up the machine-wide trees before anything else. Returns $false if any export fails.
function Backup-MachineWideRegistry {
    $machineWideBackupSources = @(
        @{ Source = 'HKLM\SOFTWARE\Classes\Installer\Products';     File = 'Installer_Products.reg' },
        @{ Source = 'HKLM\SOFTWARE\Classes\Installer\UserData';     File = 'Installer_UserData.reg' },
        @{ Source = 'HKLM\SOFTWARE\Classes\Installer\UpgradeCodes'; File = 'Installer_UpgradeCodes.reg' },
        @{ Source = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall';             File = 'Uninstall64.reg' },
        @{ Source = 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; File = 'Uninstall32.reg' }
    )
    $allBackupsSucceeded = $true
    foreach ($backupSource in $machineWideBackupSources) {
        $backupTargetFile = Join-Path $registryBackupDirectory $backupSource.File
        reg.exe export $backupSource.Source $backupTargetFile /y | Out-Null
        if (($LASTEXITCODE -ne 0) -or (-not (Test-Path $backupTargetFile))) {
            Write-RemovalLog " BACKUP FAILED: $($backupSource.Source)"
            $allBackupsSucceeded = $false
        } else {
            Write-RemovalLog " backed up $($backupSource.Source)"
        }
    }
    if (Test-Path 'C:\ProgramData\Fortinet') {
        Copy-Item 'C:\ProgramData\Fortinet' -Destination (Join-Path $registryBackupDirectory 'ProgramData_Fortinet') -Recurse -Force -ErrorAction SilentlyContinue
        Write-RemovalLog " backed up C:\ProgramData\Fortinet"
    }
    return $allBackupsSucceeded
}

# Backs up, then removes one key. Refuses non-allowlisted paths. In live passes, skips the key if its backup fails.
function Remove-RegistryKeySafely {
    param([string]$RegistryPathInput, [string]$RemovalReason)
    $nativePath   = ConvertTo-NativeRegistryPath $RegistryPathInput
    $providerPath = "Registry::$nativePath"

    if (-not (Test-IsAllowedRemovalPath $nativePath)) {
        Write-RemovalLog " REFUSED (not on allowlist): $nativePath"
        return
    }
    if (-not (Test-Path -LiteralPath $providerPath)) { return }

    if ($script:IsDryRunPass) {
        Write-RemovalLog " WOULD REMOVE: $nativePath ($RemovalReason)"
        return
    }

    if (-not (Export-RegistryKeyBackup $nativePath)) {
        Write-RemovalLog " SKIPPED (backup failed, key left untouched): $nativePath"
        return
    }
    try {
        Remove-Item -LiteralPath $providerPath -Recurse -Force -ErrorAction Stop
        Write-RemovalLog " REMOVED: $nativePath ($RemovalReason)"
    } catch {
        Write-RemovalLog " FAILED: $nativePath ($RemovalReason): $_"
    }
}

# Removes one UpgradeCodes value. Backs up the parent key first in live passes.
function Remove-UpgradeCodeValueSafely {
    param([string]$NativeKeyPath, [string]$ValueName)
    if ($NativeKeyPath -notmatch '^HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Installer\\UpgradeCodes\\[^\\]+$') {
        Write-RemovalLog " REFUSED UpgradeCodes value (path not on allowlist): $NativeKeyPath"
        return
    }
    if ($script:IsDryRunPass) {
        Write-RemovalLog " WOULD REMOVE UpgradeCodes value $ValueName under $NativeKeyPath"
        return
    }
    if (-not (Export-RegistryKeyBackup $NativeKeyPath)) {
        Write-RemovalLog " SKIPPED UpgradeCodes value (backup failed): $NativeKeyPath"
        return
    }
    Remove-ItemProperty -LiteralPath "Registry::$NativeKeyPath" -Name $ValueName -ErrorAction SilentlyContinue
    Write-RemovalLog " REMOVED UpgradeCodes value $ValueName under $NativeKeyPath"
}

# Returns native paths of FortiClient-related keys inside one loaded user hive (HKEY_USERS\<SID>).
function Get-FortiClientKeysInLoadedUserHive {
    param([string]$UserHiveProviderPath)
    $foundKeyPaths = @()

    $fortinetSoftwareKey = "$UserHiveProviderPath\Software\Fortinet"
    if (Test-Path -LiteralPath $fortinetSoftwareKey) {
        $foundKeyPaths += (ConvertTo-NativeRegistryPath $fortinetSoftwareKey)
    }

    $userInstallerProductsKey = "$UserHiveProviderPath\Software\Microsoft\Installer\Products"
    if (Test-Path -LiteralPath $userInstallerProductsKey) {
        Get-ChildItem -LiteralPath $userInstallerProductsKey | Where-Object {
            (Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue).ProductName -like '*FortiClient*'
        } | ForEach-Object { $foundKeyPaths += (ConvertTo-NativeRegistryPath $_.PSPath) }
    }

    $userUninstallKey = "$UserHiveProviderPath\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    if (Test-Path -LiteralPath $userUninstallKey) {
        Get-ChildItem -LiteralPath $userUninstallKey | Where-Object {
            (Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue).DisplayName -like '*FortiClient*'
        } | ForEach-Object { $foundKeyPaths += (ConvertTo-NativeRegistryPath $_.PSPath) }
    }

    return $foundKeyPaths
}

# One full pass: inventory, then actions. Dry pass changes nothing. Live pass makes the changes.
function Invoke-RemovalPass {
    param([bool]$IsDryRun)
    $script:IsDryRunPass = $IsDryRun
    $passLabel = if ($IsDryRun) { 'DRY RUN' } else { 'LIVE' }
    Write-RemovalLog "===== $passLabel PASS START ====="

    $uninstallRootPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    # --- Inventory (read only) ---

    # A. Add/Remove Programs entries (machine-wide)
    $fortiClientUninstallEntries = @(foreach ($uninstallRootPath in $uninstallRootPaths) {
        if (Test-Path $uninstallRootPath) {
            Get-ChildItem $uninstallRootPath | ForEach-Object {
                $uninstallEntryProperties = Get-ItemProperty $_.PSPath
                if ($uninstallEntryProperties.DisplayName -like '*FortiClient*') {
                    [pscustomobject]@{
                        ProductCodeOrKeyName = $_.PSChildName
                        NativeKeyPath        = (ConvertTo-NativeRegistryPath $_.PSPath)
                        DisplayName          = $uninstallEntryProperties.DisplayName
                        DisplayVersion       = $uninstallEntryProperties.DisplayVersion
                        QuietUninstallString = $uninstallEntryProperties.QuietUninstallString
                        UninstallString      = $uninstallEntryProperties.UninstallString
                    }
                }
            }
        }
    })

    # B. Windows Installer Products records (machine-wide), matched by ProductName
    $installerProductRecords = @()
    if (Test-Path 'HKLM:\SOFTWARE\Classes\Installer\Products') {
        $installerProductRecords = @(Get-ChildItem 'HKLM:\SOFTWARE\Classes\Installer\Products' | Where-Object {
            (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ProductName -like '*FortiClient*'
        })
    }
    $packedProductCodeNames = @($installerProductRecords | ForEach-Object { $_.PSChildName })

    # C. UserData product records (machine-wide), matched by DisplayName or packed product code
    $userDataProductKeyPaths = @()
    if (Test-Path 'HKLM:\SOFTWARE\Classes\Installer\UserData') {
        Get-ChildItem 'HKLM:\SOFTWARE\Classes\Installer\UserData' | ForEach-Object {
            $userSidProductsPath = Join-Path $_.PSPath 'Products'
            if (Test-Path $userSidProductsPath) {
                Get-ChildItem $userSidProductsPath | ForEach-Object {
                    $installPropertiesPath = Join-Path $_.PSPath 'InstallProperties'
                    $userDataDisplayName   = (Get-ItemProperty $installPropertiesPath -ErrorAction SilentlyContinue).DisplayName
                    if (($userDataDisplayName -like '*FortiClient*') -or ($packedProductCodeNames -contains $_.PSChildName)) {
                        $userDataProductKeyPaths += (ConvertTo-NativeRegistryPath $_.PSPath)
                    }
                }
            }
        }
    }

    # D. UpgradeCodes values that point at the packed product codes
    $upgradeCodeValuesToRemove = @()
    if (Test-Path 'HKLM:\SOFTWARE\Classes\Installer\UpgradeCodes') {
        Get-ChildItem 'HKLM:\SOFTWARE\Classes\Installer\UpgradeCodes' | ForEach-Object {
            $upgradeCodeValueNames = (Get-Item $_.PSPath).GetValueNames()
            foreach ($packedProductCodeName in $packedProductCodeNames) {
                if ($upgradeCodeValueNames -contains $packedProductCodeName) {
                    $upgradeCodeValuesToRemove += [pscustomobject]@{
                        NativeKeyPath = (ConvertTo-NativeRegistryPath $_.PSPath)
                        ValueName     = $packedProductCodeName
                    }
                }
            }
        }
    }

    # E. Loaded user hives only (HKEY_USERS\<SID>). Signed-out profiles are not mounted.
    $loadedUserHiveKeyTargets = @()
    Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object {
        $_.PSChildName -match '^S-1-5-21-'
    } | ForEach-Object {
        $loadedUserHiveKeyTargets += Get-FortiClientKeysInLoadedUserHive -UserHiveProviderPath "Registry::HKEY_USERS\$($_.PSChildName)"
    }

    # F. Signed-out user profiles (report only, never mounted)
    $signedOutUserProfiles = @(Get-CimInstance -ClassName Win32_UserProfile -Filter "Special=False AND Loaded=False" -ErrorAction SilentlyContinue |
        Where-Object { $_.SID -like 'S-1-5-21-*' })

    # Inventory summary
    Write-RemovalLog "Inventory:"
    Write-RemovalLog " Add/Remove Programs entries: $($fortiClientUninstallEntries.Count)"
    $fortiClientUninstallEntries | ForEach-Object { Write-RemovalLog "   - $($_.DisplayName) $($_.DisplayVersion) [$($_.ProductCodeOrKeyName)]" }
    Write-RemovalLog " Installer Products records: $($installerProductRecords.Count)"
    Write-RemovalLog " UserData product records: $($userDataProductKeyPaths.Count)"
    Write-RemovalLog " UpgradeCodes values: $($upgradeCodeValuesToRemove.Count)"
    Write-RemovalLog " Loaded user hive FortiClient keys: $($loadedUserHiveKeyTargets.Count)"
    $loadedUserHiveKeyTargets | ForEach-Object { Write-RemovalLog "   - $_" }
    Write-RemovalLog " Signed-out user profiles (not mounted, not touched): $($signedOutUserProfiles.Count)"
    $signedOutUserProfiles | ForEach-Object { Write-RemovalLog "   - $($_.SID) $($_.LocalPath)" }

    # --- Actions ---

    # 1. Stop services and processes
    Get-Service -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'Forti*' -or $_.DisplayName -like '*Forti*' } |
        ForEach-Object {
            if ($IsDryRun) { Write-RemovalLog " WOULD STOP service $($_.Name)" }
            else {
                Write-RemovalLog " stopping service $($_.Name)"
                Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue
            }
        }
    Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -like '*\Fortinet\*' } |
        ForEach-Object {
            if ($IsDryRun) { Write-RemovalLog " WOULD STOP process $($_.Name)" }
            else {
                Write-RemovalLog " stopping process $($_.Name)"
                Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
            }
        }

    # 2. Uninstall each Add/Remove Programs entry
    foreach ($fortiClientEntry in $fortiClientUninstallEntries) {
        $uninstallCommand = if ($fortiClientEntry.QuietUninstallString) {
            $fortiClientEntry.QuietUninstallString
        } else {
            $fortiClientEntry.UninstallString
        }

        if ($fortiClientEntry.ProductCodeOrKeyName -match '^\{[0-9A-Fa-f\-]{36}\}$') {
            $msiLogPath   = Join-Path $fortiClientLogDirectory ("msi_uninstall_{0}.log" -f ($fortiClientEntry.ProductCodeOrKeyName -replace '[{}]', ''))
            $msiArguments = "/x $($fortiClientEntry.ProductCodeOrKeyName) /qn /norestart /l*v `"$msiLogPath`""
            if ($IsDryRun) { Write-RemovalLog " WOULD RUN: msiexec.exe $msiArguments"; continue }
            Write-RemovalLog " running: msiexec.exe $msiArguments"
            $uninstallProcess = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArguments -PassThru
        }
        elseif ($uninstallCommand) {
            if ($IsDryRun) { Write-RemovalLog " WOULD RUN non-MSI uninstall: $uninstallCommand"; continue }
            Write-RemovalLog " running non-MSI uninstall: $uninstallCommand"
            $uninstallProcess = Start-Process -FilePath 'cmd.exe' -ArgumentList "/c `"$uninstallCommand`"" -PassThru
        }
        else {
            Write-RemovalLog " no uninstall command for $($fortiClientEntry.DisplayName), skipping"
            continue
        }

        if (-not $uninstallProcess.WaitForExit(900000)) {
            Write-RemovalLog " timed out after 15 minutes, killing process"
            $uninstallProcess.Kill()
        }
        # 0 = success, 1605 = not installed, 3010 = reboot required
        Write-RemovalLog " exit code: $($uninstallProcess.ExitCode)"
    }

    # 3. Machine-wide leftover keys
    foreach ($installerProductRecord in $installerProductRecords) {
        Remove-RegistryKeySafely -RegistryPathInput $installerProductRecord.PSPath -RemovalReason 'Installer Products record'
    }
    foreach ($userDataProductKeyPath in $userDataProductKeyPaths) {
        Remove-RegistryKeySafely -RegistryPathInput $userDataProductKeyPath -RemovalReason 'UserData product record'
    }
    foreach ($upgradeCodeValue in $upgradeCodeValuesToRemove) {
        Remove-UpgradeCodeValueSafely -NativeKeyPath $upgradeCodeValue.NativeKeyPath -ValueName $upgradeCodeValue.ValueName
    }
    foreach ($fortiClientEntry in $fortiClientUninstallEntries) {
        if (Test-Path -LiteralPath "Registry::$($fortiClientEntry.NativeKeyPath)") {
            Remove-RegistryKeySafely -RegistryPathInput $fortiClientEntry.NativeKeyPath -RemovalReason 'Add/Remove Programs key'
        }
    }

    # 4. Loaded user hives
    foreach ($loadedUserHiveKeyTarget in $loadedUserHiveKeyTargets) {
        Remove-RegistryKeySafely -RegistryPathInput $loadedUserHiveKeyTarget -RemovalReason 'loaded user hive'
    }

    # 5. Install and data folders (exact paths only)
    $fortinetFolderPaths = @(
        'C:\Program Files\Fortinet',
        'C:\Program Files (x86)\Fortinet',
        'C:\ProgramData\Fortinet'
    )
    foreach ($fortinetFolderPath in $fortinetFolderPaths) {
        if (-not (Test-Path -LiteralPath $fortinetFolderPath)) { continue }
        if ($IsDryRun) { Write-RemovalLog " WOULD REMOVE folder $fortinetFolderPath"; continue }
        Remove-Item -LiteralPath $fortinetFolderPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-RemovalLog " REMOVED folder $fortinetFolderPath"
    }

    Write-RemovalLog "===== $passLabel PASS END ====="
}

# ============================ MAIN ============================

Write-RemovalLog "Step 1: backing up registry before any change"
if (-not (Backup-MachineWideRegistry)) {
    Write-RemovalLog "Aborting: a machine-wide backup failed. Nothing was changed."
    return
}

Write-RemovalLog "Step 2: dry run (no changes)"
Invoke-RemovalPass -IsDryRun $true

Write-Host ""
Write-Host "Dry run complete. Review the log before continuing: $removalLogFilePath"
$typedConfirmation = Read-Host "Type DELETE (case sensitive) to perform the removal listed above, or anything else to stop"
if ($typedConfirmation -cne 'DELETE') {
    Write-RemovalLog "Stopped by operator after dry run. Nothing was removed."
    return
}

Write-RemovalLog "Step 3: live removal (per-key backups are taken before each deletion)"
Invoke-RemovalPass -IsDryRun $false

Write-RemovalLog "Step 4: verification"
$remainingUninstallEntries = @()
foreach ($uninstallRootPath in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
    if (Test-Path $uninstallRootPath) {
        $remainingUninstallEntries += Get-ChildItem $uninstallRootPath | Where-Object {
            (Get-ItemProperty $_.PSPath).DisplayName -like '*FortiClient*'
        }
    }
}
Write-RemovalLog "Remaining machine-wide Add/Remove entries: $($remainingUninstallEntries.Count)"
Write-RemovalLog "Signed-out profiles were not modified. Their FortiClient keys remain until those users sign in or are cleaned up separately."
Write-RemovalLog "Done. Reboot before reinstalling. Log: $removalLogFilePath"