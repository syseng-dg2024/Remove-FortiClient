#Requires -RunAsAdministrator

$ErrorActionPreference = 'Continue'
$runStamp                = Get-Date -Format 'yyyyMMdd_HHmmss'
$backupRunDirectory      = Join-Path $PSScriptRoot "Backup\Backup_$runStamp"
$registryBackupDirectory = Join-Path $backupRunDirectory 'Registry'
$fileBackupDirectory     = Join-Path $backupRunDirectory 'Files'
$taskBackupDirectory     = Join-Path $backupRunDirectory 'ScheduledTasks'
$manifestFilePath        = Join-Path $backupRunDirectory 'manifest.csv'
$removalLogFilePath      = Join-Path $PSScriptRoot "removal_$runStamp.log"
New-Item -ItemType Directory -Path $registryBackupDirectory, $fileBackupDirectory, $taskBackupDirectory -Force | Out-Null

$fortinetFolderPaths = @(
    'C:\Program Files\Fortinet',
    'C:\Program Files (x86)\Fortinet',
    'C:\ProgramData\Fortinet'
)

$script:IsDryRunPass            = $true
$script:VerifiedRegistryBackups = @{}   # native key path -> verified backup file
$script:VerifiedTaskBackups     = @{}   # task path + name -> verified backup file
$script:ManifestRows            = New-Object System.Collections.Generic.List[object]
$script:RegistryBackupCounter   = 0
$script:DelayedDeleteCount      = 0

# Windows API used to schedule locked files for deletion at the next reboot
if (-not ('FortiCleanup.NativeFile' -as [type])) {
    Add-Type -Namespace FortiCleanup -Name NativeFile -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
'@
}

function Write-RemovalLog {
    param([string]$Message)
    $logLine = "[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'), $Message
    Write-Host $logLine
    Add-Content -Path $removalLogFilePath -Value $logLine
}

function Add-ManifestRow {
    param([string]$ItemType, [string]$SourceLocation, [string]$BackupLocation, [long]$SizeBytes, [bool]$Verified, [string]$Note)
    $script:ManifestRows.Add([pscustomobject]@{
        Timestamp      = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')
        ItemType       = $ItemType
        SourceLocation = $SourceLocation
        BackupLocation = $BackupLocation
        SizeBytes      = $SizeBytes
        Verified       = $Verified
        Note           = $Note
    })
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

# Only these key shapes may ever be deleted or exported. Anything else is refused.
$allowedNativeRemovalPatterns = @(
    '^HKEY_USERS\\[^\\]+\\Software\\Fortinet$',
    '^HKEY_USERS\\[^\\]+\\Software\\Microsoft\\Installer\\Products\\[^\\]+$',
    '^HKEY_USERS\\[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\[^\\]+$',
    '^HKEY_USERS\\[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\Run(Once)?$',
    '^HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Installer\\Products\\[^\\]+$',
    '^HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Installer\\UserData\\[^\\]+\\Products\\[^\\]+$',
    '^HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\[^\\]+$',
    '^HKEY_LOCAL_MACHINE\\SOFTWARE\\(WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run(Once)?$',
    '^HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\[^\\]+$',
    '^HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Installer\\UpgradeCodes\\[^\\]+$'
)

function Test-IsAllowedRemovalPath {
    param([string]$NativePath)
    foreach ($allowedPattern in $allowedNativeRemovalPatterns) {
        if ($NativePath -match $allowedPattern) { return $true }
    }
    return $false
}

# Returns native paths of FortiClient keys inside one loaded user hive (HKEY_USERS\<SID>).
function Get-FortiClientKeysInLoadedUserHive {
    param([string]$UserHiveProviderPath)
    $foundKeyPaths = @()

    $fortinetSoftwareKey = "$UserHiveProviderPath\Software\Fortinet"
    if (Test-Path -LiteralPath $fortinetSoftwareKey) {
        $foundKeyPaths += (ConvertTo-NativeRegistryPath $fortinetSoftwareKey)
    }

    $userInstallerProductsKey = "$UserHiveProviderPath\Software\Microsoft\Installer\Products"
    if (Test-Path -LiteralPath $userInstallerProductsKey) {
        foreach ($userProductKey in (Get-ChildItem -LiteralPath $userInstallerProductsKey)) {
            if ((Get-ItemProperty -LiteralPath $userProductKey.PSPath -ErrorAction SilentlyContinue).ProductName -like '*FortiClient*') {
                $foundKeyPaths += (ConvertTo-NativeRegistryPath $userProductKey.PSPath)
            }
        }
    }

    $userUninstallKey = "$UserHiveProviderPath\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    if (Test-Path -LiteralPath $userUninstallKey) {
        foreach ($userUninstallEntry in (Get-ChildItem -LiteralPath $userUninstallKey)) {
            if ((Get-ItemProperty -LiteralPath $userUninstallEntry.PSPath -ErrorAction SilentlyContinue).DisplayName -like '*FortiClient*') {
                $foundKeyPaths += (ConvertTo-NativeRegistryPath $userUninstallEntry.PSPath)
            }
        }
    }

    return $foundKeyPaths
}

# Finds FortiClient services (name or binary path)
function Get-FortiServices {
    return @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -like 'Forti*' -or $_.Name -like 'FA_*' -or $_.Name -like 'FCT_*' -or $_.PathName -like '*\Fortinet\*'
    })
}

# Finds FortiClient scheduled tasks (name or action path)
function Get-FortiScheduledTasks {
    return @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $_.TaskName -like '*Forti*' -or @($_.Actions | Where-Object { $_.Execute -like '*Fortinet*' }).Count -gt 0
    })
}

# Finds Run and RunOnce values that start FortiClient (machine-wide and loaded user hives)
function Get-FortiRunValues {
    $runKeyPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($hiveKey in (Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue)) {
        if ($hiveKey.PSChildName -notmatch '^S-1-5-21-') { continue }
        $runKeyPaths += "Registry::HKEY_USERS\$($hiveKey.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Run"
        $runKeyPaths += "Registry::HKEY_USERS\$($hiveKey.PSChildName)\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    }

    $fortiRunValues = @()
    foreach ($runKeyPath in $runKeyPaths) {
        if (-not (Test-Path -LiteralPath $runKeyPath)) { continue }
        $runKeyProperties = Get-ItemProperty -LiteralPath $runKeyPath -ErrorAction SilentlyContinue
        foreach ($runProperty in $runKeyProperties.PSObject.Properties) {
            if ($runProperty.Name -like 'PS*') { continue }
            $runValueText = [string]$runProperty.Value
            if ($runProperty.Name -like '*Forti*' -or $runValueText -like '*Fortinet*' -or $runValueText -like '*FortiTray*') {
                $fortiRunValues += [pscustomobject]@{
                    NativeKeyPath = (ConvertTo-NativeRegistryPath $runKeyPath)
                    ValueName     = $runProperty.Name
                    Data          = $runValueText
                }
            }
        }
    }
    return $fortiRunValues
}

# Finds FortiClient shortcuts on the public desktop, Start menu, and every user's desktop and Start menu
function Get-FortiShortcuts {
    $shortcutSearchFolders = @(
        'C:\Users\Public\Desktop',
        'C:\ProgramData\Microsoft\Windows\Start Menu\Programs'
    )
    foreach ($userFolder in (Get-ChildItem -LiteralPath 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue)) {
        $shortcutSearchFolders += "$($userFolder.FullName)\Desktop"
        $shortcutSearchFolders += "$($userFolder.FullName)\OneDrive\Desktop"
        $shortcutSearchFolders += "$($userFolder.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs"
    }

    $fortiShortcutPaths = @()
    foreach ($searchFolder in $shortcutSearchFolders) {
        if (-not (Test-Path -LiteralPath $searchFolder)) { continue }
        foreach ($shortcutItem in (Get-ChildItem -LiteralPath $searchFolder -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*Forti*' })) {
            $fortiShortcutPaths += $shortcutItem.FullName
        }
    }
    return $fortiShortcutPaths
}

# Read-only inventory of everything the removal would touch.
function Get-RemovalInventory {
    Write-RemovalLog "Building inventory (read only)"
    $uninstallRootPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )

    # A. Add/Remove Programs entries (machine-wide)
    $uninstallEntries = @()
    foreach ($uninstallRootPath in $uninstallRootPaths) {
        if (-not (Test-Path $uninstallRootPath)) { continue }
        foreach ($uninstallKey in (Get-ChildItem $uninstallRootPath)) {
            $entryProperties = Get-ItemProperty $uninstallKey.PSPath
            if ($entryProperties.DisplayName -like '*FortiClient*') {
                $uninstallEntries += [pscustomobject]@{
                    ProductCodeOrKeyName = $uninstallKey.PSChildName
                    NativeKeyPath        = (ConvertTo-NativeRegistryPath $uninstallKey.PSPath)
                    DisplayName          = $entryProperties.DisplayName
                    DisplayVersion       = $entryProperties.DisplayVersion
                    QuietUninstallString = $entryProperties.QuietUninstallString
                    UninstallString      = $entryProperties.UninstallString
                }
            }
        }
    }

    # B. Windows Installer Products records (machine-wide), matched by ProductName
    $installerRecords = @()
    if (Test-Path 'HKLM:\SOFTWARE\Classes\Installer\Products') {
        foreach ($installerRecord in (Get-ChildItem 'HKLM:\SOFTWARE\Classes\Installer\Products')) {
            if ((Get-ItemProperty $installerRecord.PSPath -ErrorAction SilentlyContinue).ProductName -like '*FortiClient*') {
                $installerRecords += $installerRecord
            }
        }
    }
    $packedProductCodeNames = @($installerRecords | ForEach-Object { $_.PSChildName })

    # C. UserData product records (machine-wide)
    $userDataKeys = @()
    if (Test-Path 'HKLM:\SOFTWARE\Classes\Installer\UserData') {
        foreach ($userSidKey in (Get-ChildItem 'HKLM:\SOFTWARE\Classes\Installer\UserData')) {
            $userSidProductsPath = Join-Path $userSidKey.PSPath 'Products'
            if (-not (Test-Path $userSidProductsPath)) { continue }
            foreach ($userDataProduct in (Get-ChildItem $userSidProductsPath)) {
                $installPropertiesPath = Join-Path $userDataProduct.PSPath 'InstallProperties'
                $userDataDisplayName   = (Get-ItemProperty $installPropertiesPath -ErrorAction SilentlyContinue).DisplayName
                if (($userDataDisplayName -like '*FortiClient*') -or ($packedProductCodeNames -contains $userDataProduct.PSChildName)) {
                    $userDataKeys += (ConvertTo-NativeRegistryPath $userDataProduct.PSPath)
                }
            }
        }
    }

    # D. UpgradeCodes values that point at the packed product codes
    $upgradeCodeValues = @()
    if (Test-Path 'HKLM:\SOFTWARE\Classes\Installer\UpgradeCodes') {
        foreach ($upgradeCodeKey in (Get-ChildItem 'HKLM:\SOFTWARE\Classes\Installer\UpgradeCodes')) {
            $upgradeCodeValueNames = (Get-Item $upgradeCodeKey.PSPath).GetValueNames()
            foreach ($packedProductCodeName in $packedProductCodeNames) {
                if ($upgradeCodeValueNames -contains $packedProductCodeName) {
                    $upgradeCodeValues += [pscustomobject]@{
                        NativeKeyPath = (ConvertTo-NativeRegistryPath $upgradeCodeKey.PSPath)
                        ValueName     = $packedProductCodeName
                    }
                }
            }
        }
    }

    # E. Loaded user hives only (HKEY_USERS\<SID>). Signed-out profiles are not mounted.
    $loadedUserKeys = @()
    foreach ($hiveKey in (Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue)) {
        if ($hiveKey.PSChildName -notmatch '^S-1-5-21-') { continue }
        $loadedUserKeys += Get-FortiClientKeysInLoadedUserHive -UserHiveProviderPath "Registry::HKEY_USERS\$($hiveKey.PSChildName)"
    }

    # F. Signed-out profiles (report only, never mounted)
    $signedOutProfiles = @(Get-CimInstance -ClassName Win32_UserProfile -Filter "Special=False AND Loaded=False" -ErrorAction SilentlyContinue |
        Where-Object { $_.SID -like 'S-1-5-21-*' })

    # G. Services, H. scheduled tasks, I. Run values, J. shortcuts
    $fortiServices   = Get-FortiServices
    $fortiTasks      = Get-FortiScheduledTasks
    $fortiRunValues  = Get-FortiRunValues
    $fortiShortcuts  = Get-FortiShortcuts

    Write-RemovalLog "Inventory:"
    Write-RemovalLog " Add/Remove Programs entries: $($uninstallEntries.Count)"
    foreach ($uninstallEntry in $uninstallEntries) { Write-RemovalLog "   - $($uninstallEntry.DisplayName) $($uninstallEntry.DisplayVersion) [$($uninstallEntry.ProductCodeOrKeyName)]" }
    Write-RemovalLog " Installer Products records: $($installerRecords.Count)"
    Write-RemovalLog " UserData product records: $($userDataKeys.Count)"
    Write-RemovalLog " UpgradeCodes values: $($upgradeCodeValues.Count)"
    Write-RemovalLog " Loaded user hive FortiClient keys: $($loadedUserKeys.Count)"
    foreach ($loadedUserKey in $loadedUserKeys) { Write-RemovalLog "   - $loadedUserKey" }
    Write-RemovalLog " Services: $($fortiServices.Count)"
    foreach ($fortiService in $fortiServices) { Write-RemovalLog "   - $($fortiService.Name) ($($fortiService.State), start: $($fortiService.StartMode))" }
    Write-RemovalLog " Scheduled tasks: $($fortiTasks.Count)"
    foreach ($fortiTask in $fortiTasks) { Write-RemovalLog "   - $($fortiTask.TaskPath)$($fortiTask.TaskName)" }
    Write-RemovalLog " Run/RunOnce values: $($fortiRunValues.Count)"
    foreach ($fortiRunValue in $fortiRunValues) { Write-RemovalLog "   - $($fortiRunValue.NativeKeyPath) [$($fortiRunValue.ValueName)]" }
    Write-RemovalLog " Shortcuts: $($fortiShortcuts.Count)"
    foreach ($fortiShortcut in $fortiShortcuts) { Write-RemovalLog "   - $fortiShortcut" }
    Write-RemovalLog " Signed-out profiles (not mounted, not touched): $($signedOutProfiles.Count)"
    foreach ($signedOutProfile in $signedOutProfiles) { Write-RemovalLog "   - $($signedOutProfile.SID) $($signedOutProfile.LocalPath)" }

    return [pscustomobject]@{
        UninstallEntries  = $uninstallEntries
        InstallerRecords  = $installerRecords
        UserDataKeys      = $userDataKeys
        UpgradeCodeValues = $upgradeCodeValues
        LoadedUserKeys    = $loadedUserKeys
        SignedOutProfiles = $signedOutProfiles
        Services          = $fortiServices
        ScheduledTasks    = $fortiTasks
        RunValues         = $fortiRunValues
        Shortcuts         = $fortiShortcuts
    }
}

# Exports one registry key and verifies the .reg file is present and non-empty.
function Export-RegistryKeyVerified {
    param([string]$NativePath)
    if (-not (Test-IsAllowedRemovalPath $NativePath)) {
        Add-ManifestRow 'Registry' $NativePath '' 0 $false 'Refused: not on allowlist'
        return $false
    }
    $script:RegistryBackupCounter++
    $regExeKeyPath    = $NativePath -replace '^HKEY_USERS', 'HKU' -replace '^HKEY_LOCAL_MACHINE', 'HKLM'
    $sanitizedKeyName = $NativePath -replace '[^A-Za-z0-9]', '_'
    if ($sanitizedKeyName.Length -gt 120) { $sanitizedKeyName = $sanitizedKeyName.Substring(0, 120) }
    $backupFilePath = Join-Path $registryBackupDirectory ("{0:D4}_{1}.reg" -f $script:RegistryBackupCounter, $sanitizedKeyName)

    reg.exe export $regExeKeyPath $backupFilePath /y | Out-Null
    $exportSucceeded = ($LASTEXITCODE -eq 0) -and (Test-Path -LiteralPath $backupFilePath)
    $backupSize = if ($exportSucceeded) { (Get-Item -LiteralPath $backupFilePath).Length } else { 0 }
    $headerIsValid = $exportSucceeded -and ((Get-Content -LiteralPath $backupFilePath -TotalCount 1) -like '*Windows Registry Editor*')
    $verified = [bool]($headerIsValid -and ($backupSize -gt 0))

    Add-ManifestRow 'Registry' $NativePath $backupFilePath $backupSize $verified ''
    if ($verified) { $script:VerifiedRegistryBackups[$NativePath] = $backupFilePath }
    return $verified
}

# Exports one scheduled task to XML and verifies the file is non-empty.
function Export-ScheduledTaskVerified {
    param($Task)
    $taskKey  = "$($Task.TaskPath)$($Task.TaskName)"
    $taskFile = Join-Path $taskBackupDirectory (($taskKey -replace '[^A-Za-z0-9]', '_') + '.xml')
    try {
        $taskXml = Export-ScheduledTask -TaskName $Task.TaskName -TaskPath $Task.TaskPath -ErrorAction Stop
        Set-Content -LiteralPath $taskFile -Value $taskXml -Encoding UTF8
    } catch {
        Write-RemovalLog " task export error: $($_.Exception.Message)"
    }
    $taskSize = if (Test-Path -LiteralPath $taskFile) { (Get-Item -LiteralPath $taskFile).Length } else { 0 }
    $taskVerified = ($taskSize -gt 0) -and [bool](Select-String -LiteralPath $taskFile -Pattern '<Task' -Quiet -ErrorAction SilentlyContinue)
    Add-ManifestRow 'ScheduledTask' $taskKey $taskFile $taskSize $taskVerified ''
    if ($taskVerified) { $script:VerifiedTaskBackups[$taskKey] = $taskFile }
    return $taskVerified
}

# Copies a shortcut or folder (best effort). Removal is not blocked by this.
function Backup-ItemBestEffort {
    param([string]$SourcePath, [int]$Index)
    $shortcutBackupFolder = Join-Path $fileBackupDirectory 'Shortcuts'
    New-Item -ItemType Directory -Path $shortcutBackupFolder -Force | Out-Null
    $itemName    = Split-Path -Leaf $SourcePath
    $destination = Join-Path $shortcutBackupFolder ("{0:D3}_{1}" -f $Index, ($itemName -replace '[^A-Za-z0-9._-]', '_'))
    Copy-Item -LiteralPath $SourcePath -Destination $destination -Recurse -Force -ErrorAction SilentlyContinue
    $copied = Test-Path -LiteralPath $destination
    Add-ManifestRow 'Shortcut' $SourcePath $destination 0 $copied 'best effort'
    Write-RemovalLog " shortcut backup (best effort) $(if ($copied) { 'copied' } else { 'failed' }): $SourcePath"
}

# Copies a Fortinet folder with robocopy (best effort).
function Backup-FolderBestEffort {
    param([string]$SourceFolder)
    $folderBackupName  = $SourceFolder -replace '[^A-Za-z0-9]', '_'
    $destinationFolder = Join-Path $fileBackupDirectory $folderBackupName

    robocopy.exe $SourceFolder $destinationFolder /E /COPY:DAT /R:1 /W:1 /NP /NFL /NDL /NJH /NJS | Out-Null
    $robocopyExitCode = $LASTEXITCODE
    $copyCompleted = ($robocopyExitCode -lt 8)
    $copyStatus = if ($copyCompleted) { 'copied' } else { "incomplete (robocopy exit $robocopyExitCode)" }

    Add-ManifestRow 'Folder' $SourceFolder $destinationFolder 0 $copyCompleted "best effort, $copyStatus"
    Write-RemovalLog " file backup (best effort) ${copyStatus}: $SourceFolder -> $destinationFolder"
}

# Backs up and verifies everything the removal would touch. Returns $false if the machine-wide backup fails.
function Backup-AllTargetsVerified {
    param($Inventory)
    Write-RemovalLog "Backing up and verifying everything the removal would touch"

    # Whole machine-wide trees (must succeed)
    $machineWideSources = @(
        @{ Source = 'HKLM\SOFTWARE\Classes\Installer\Products';                             File = 'Installer_Products.reg' },
        @{ Source = 'HKLM\SOFTWARE\Classes\Installer\UserData';                             File = 'Installer_UserData.reg' },
        @{ Source = 'HKLM\SOFTWARE\Classes\Installer\UpgradeCodes';                         File = 'Installer_UpgradeCodes.reg' },
        @{ Source = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall';             File = 'Uninstall64.reg' },
        @{ Source = 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; File = 'Uninstall32.reg' }
    )
    $machineWideBackupsOk = $true
    foreach ($machineWideSource in $machineWideSources) {
        reg.exe query $machineWideSource.Source | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Add-ManifestRow 'Registry' $machineWideSource.Source '' 0 $true 'Not present on this machine'
            Write-RemovalLog " not present, nothing to back up: $($machineWideSource.Source)"
            continue
        }
        $machineWideFile = Join-Path $registryBackupDirectory $machineWideSource.File
        reg.exe export $machineWideSource.Source $machineWideFile /y | Out-Null
        $machineWideSize = if (Test-Path -LiteralPath $machineWideFile) { (Get-Item -LiteralPath $machineWideFile).Length } else { 0 }
        $machineWideVerified = ($LASTEXITCODE -eq 0) -and ($machineWideSize -gt 0)
        Add-ManifestRow 'Registry' $machineWideSource.Source $machineWideFile $machineWideSize $machineWideVerified 'Whole-tree export'
        if (-not $machineWideVerified) { $machineWideBackupsOk = $false }
        Write-RemovalLog " $(if ($machineWideVerified) { 'verified' } else { 'FAILED' }): $($machineWideSource.Source)"
    }
    if (-not $machineWideBackupsOk) { return $false }

    # Every individual registry key the removal would delete or depend on
    $keysToBackup = @()
    foreach ($uninstallEntry in $Inventory.UninstallEntries) { $keysToBackup += $uninstallEntry.NativeKeyPath }
    foreach ($installerRecord in $Inventory.InstallerRecords) { $keysToBackup += (ConvertTo-NativeRegistryPath $installerRecord.PSPath) }
    foreach ($userDataKey in $Inventory.UserDataKeys) { $keysToBackup += $userDataKey }
    foreach ($loadedUserKey in $Inventory.LoadedUserKeys) { $keysToBackup += $loadedUserKey }
    foreach ($upgradeCodeValue in $Inventory.UpgradeCodeValues) { $keysToBackup += $upgradeCodeValue.NativeKeyPath }
    foreach ($runValue in $Inventory.RunValues) { $keysToBackup += $runValue.NativeKeyPath }

    foreach ($nativeKeyPath in ($keysToBackup | Where-Object { $_ } | Select-Object -Unique)) {
        $keyVerified = Export-RegistryKeyVerified -NativePath $nativeKeyPath
        Write-RemovalLog " $(if ($keyVerified) { 'verified' } else { 'FAILED' }) key: $nativeKeyPath"
    }

    # Scheduled tasks (exported to XML)
    foreach ($fortiTask in $Inventory.ScheduledTasks) {
        $taskVerified = Export-ScheduledTaskVerified -Task $fortiTask
        Write-RemovalLog " $(if ($taskVerified) { 'verified' } else { 'FAILED' }) task: $($fortiTask.TaskPath)$($fortiTask.TaskName)"
    }

    # Shortcuts and Fortinet folders (best effort)
    $shortcutIndex = 0
    foreach ($shortcutPath in $Inventory.Shortcuts) {
        $shortcutIndex++
        Backup-ItemBestEffort -SourcePath $shortcutPath -Index $shortcutIndex
    }
    foreach ($fortinetFolderPath in $fortinetFolderPaths) {
        if (-not (Test-Path -LiteralPath $fortinetFolderPath)) { continue }
        Backup-FolderBestEffort -SourceFolder $fortinetFolderPath
    }

    $manifestRows = $script:ManifestRows
    $manifestRows | Export-Csv -LiteralPath $manifestFilePath -NoTypeInformation -Encoding UTF8
    $verifiedCount = @($manifestRows | Where-Object { $_.Verified }).Count
    $failedCount   = @($manifestRows | Where-Object { -not $_.Verified }).Count
    Write-RemovalLog "Manifest written: $manifestFilePath ($verifiedCount verified, $failedCount failed or skipped)"
    return $true
}

# Stops FortiClient processes. Live runs repeat up to 3 times in case a process restarts.
function Stop-FortiClientProcesses {
    param([bool]$IsDryRun)
    $killPassCount = if ($IsDryRun) { 1 } else { 3 }
    for ($killPass = 1; $killPass -le $killPassCount; $killPass++) {
        $fortiProcesses = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -like '*\Fortinet\*' })
        if ($fortiProcesses.Count -eq 0) { break }
        foreach ($fortiProcess in $fortiProcesses) {
            if ($IsDryRun) { Write-RemovalLog " WOULD STOP process $($fortiProcess.Name)"; continue }
            Write-RemovalLog " stopping process $($fortiProcess.Name)"
            Stop-Process -Id $fortiProcess.Id -Force -ErrorAction SilentlyContinue
        }
        if (-not $IsDryRun) { Start-Sleep -Seconds 2 }
    }
}

# Removes one registry key only if its backup was verified in this run.
function Remove-RegistryKeySafely {
    param([string]$RegistryPathInput, [string]$RemovalReason)
    $nativePath   = ConvertTo-NativeRegistryPath $RegistryPathInput
    $providerPath = "Registry::$nativePath"

    if (-not (Test-IsAllowedRemovalPath $nativePath)) {
        Write-RemovalLog " REFUSED (not on allowlist): $nativePath"
        return
    }
    if (-not (Test-Path -LiteralPath $providerPath)) { return }
    if (-not $script:VerifiedRegistryBackups.ContainsKey($nativePath)) {
        Write-RemovalLog " SKIPPED (no verified backup): $nativePath"
        return
    }
    $backupFile = $script:VerifiedRegistryBackups[$nativePath]

    if ($script:IsDryRunPass) {
        Write-RemovalLog " WOULD REMOVE: $nativePath ($RemovalReason), backup: $backupFile"
        return
    }
    try {
        Remove-Item -LiteralPath $providerPath -Recurse -Force -ErrorAction Stop
        Write-RemovalLog " REMOVED: $nativePath ($RemovalReason)"
    } catch {
        Write-RemovalLog " FAILED: $nativePath ($RemovalReason): $($_.Exception.Message)"
    }
}

# Removes one UpgradeCodes value only if its parent key backup was verified.
function Remove-UpgradeCodeValueSafely {
    param([string]$NativeKeyPath, [string]$ValueName)
    if (-not (Test-IsAllowedRemovalPath $NativeKeyPath)) {
        Write-RemovalLog " REFUSED UpgradeCodes value (not on allowlist): $NativeKeyPath"
        return
    }
    if (-not $script:VerifiedRegistryBackups.ContainsKey($NativeKeyPath)) {
        Write-RemovalLog " SKIPPED UpgradeCodes value (no verified backup): $NativeKeyPath"
        return
    }
    if ($script:IsDryRunPass) {
        Write-RemovalLog " WOULD REMOVE UpgradeCodes value $ValueName under $NativeKeyPath"
        return
    }
    try {
        Remove-ItemProperty -LiteralPath "Registry::$NativeKeyPath" -Name $ValueName -ErrorAction Stop
        Write-RemovalLog " REMOVED UpgradeCodes value $ValueName under $NativeKeyPath"
    } catch {
        Write-RemovalLog " FAILED UpgradeCodes value $ValueName : $($_.Exception.Message)"
    }
}

# Removes one Run/RunOnce value only if its key backup was verified.
function Remove-RunValueSafely {
    param($RunValue)
    if (-not (Test-IsAllowedRemovalPath $RunValue.NativeKeyPath)) {
        Write-RemovalLog " REFUSED Run value (not on allowlist): $($RunValue.NativeKeyPath)"
        return
    }
    if (-not $script:VerifiedRegistryBackups.ContainsKey($RunValue.NativeKeyPath)) {
        Write-RemovalLog " SKIPPED Run value (no verified backup): $($RunValue.NativeKeyPath) [$($RunValue.ValueName)]"
        return
    }
    if ($script:IsDryRunPass) {
        Write-RemovalLog " WOULD REMOVE Run value $($RunValue.ValueName) under $($RunValue.NativeKeyPath)"
        return
    }
    try {
        Remove-ItemProperty -LiteralPath "Registry::$($RunValue.NativeKeyPath)" -Name $RunValue.ValueName -ErrorAction Stop
        Write-RemovalLog " REMOVED Run value $($RunValue.ValueName) under $($RunValue.NativeKeyPath)"
    } catch {
        Write-RemovalLog " FAILED Run value $($RunValue.ValueName): $($_.Exception.Message)"
    }
}

# Unregisters one scheduled task only if its XML backup was verified.
function Remove-FortiScheduledTaskSafely {
    param($Task)
    $taskKey = "$($Task.TaskPath)$($Task.TaskName)"
    if (-not $script:VerifiedTaskBackups.ContainsKey($taskKey)) {
        Write-RemovalLog " SKIPPED task (no verified backup): $taskKey"
        return
    }
    if ($script:IsDryRunPass) {
        Write-RemovalLog " WOULD REMOVE task $taskKey, backup: $($script:VerifiedTaskBackups[$taskKey])"
        return
    }
    try {
        Unregister-ScheduledTask -TaskName $Task.TaskName -TaskPath $Task.TaskPath -Confirm:$false -ErrorAction Stop
        Write-RemovalLog " REMOVED task $taskKey"
    } catch {
        Write-RemovalLog " FAILED task $taskKey : $($_.Exception.Message)"
    }
}

# Deletes a file or folder. Anything still locked is scheduled for deletion at the next reboot.
function Remove-PathWithFallback {
    param([string]$TargetPath, [string]$ItemKind)
    if (-not (Test-Path -LiteralPath $TargetPath)) { return }
    if ($script:IsDryRunPass) { Write-RemovalLog " WOULD REMOVE $ItemKind $TargetPath"; return }

    Remove-Item -LiteralPath $TargetPath -Recurse -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path -LiteralPath $TargetPath)) { Write-RemovalLog " REMOVED $ItemKind $TargetPath"; return }

    # Some items are still locked: delete the rest individually, deepest first
    $remainingChildren = @(Get-ChildItem -LiteralPath $TargetPath -Recurse -Force -ErrorAction SilentlyContinue |
        Sort-Object { $_.FullName.Length } -Descending)
    foreach ($remainingChild in $remainingChildren) {
        try {
            Remove-Item -LiteralPath $remainingChild.FullName -Force -ErrorAction Stop
        } catch {
            Write-RemovalLog " locked, scheduled for deletion at reboot: $($remainingChild.FullName) ($($_.Exception.Message))"
            if ([FortiCleanup.NativeFile]::MoveFileEx($remainingChild.FullName, $null, 4)) { $script:DelayedDeleteCount++ }
        }
    }
    Remove-Item -LiteralPath $TargetPath -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $TargetPath) {
        if ([FortiCleanup.NativeFile]::MoveFileEx($TargetPath, $null, 4)) { $script:DelayedDeleteCount++ }
        Write-RemovalLog " scheduled for removal at reboot: $TargetPath"
    } else {
        Write-RemovalLog " REMOVED $ItemKind $TargetPath"
    }
}

# One pass over the inventory. Dry pass changes nothing. Live pass makes the changes.
function Invoke-RemovalPass {
    param([bool]$IsDryRun, $Inventory)
    $script:IsDryRunPass = $IsDryRun
    $passLabel = if ($IsDryRun) { 'DRY RUN' } else { 'LIVE' }
    Write-RemovalLog "===== $passLabel PASS START ====="

    # 1. Disable and stop services first so they cannot restart FortiClient
    foreach ($fortiService in $Inventory.Services) {
        if ($IsDryRun) { Write-RemovalLog " WOULD DISABLE and STOP service $($fortiService.Name)"; continue }
        Write-RemovalLog " disabling and stopping service $($fortiService.Name)"
        Set-Service -Name $fortiService.Name -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service -Name $fortiService.Name -Force -ErrorAction SilentlyContinue
    }
    Stop-FortiClientProcesses -IsDryRun $IsDryRun

    # 2. Scheduled tasks that launch FortiClient
    foreach ($fortiTask in $Inventory.ScheduledTasks) {
        Remove-FortiScheduledTaskSafely -Task $fortiTask
    }

    # 3. Run/RunOnce autostart values
    foreach ($runValue in $Inventory.RunValues) {
        Remove-RunValueSafely -RunValue $runValue
    }

    # 4. Stop any FortiClient process that was restarted before the autostart entries were removed
    Stop-FortiClientProcesses -IsDryRun $IsDryRun

    # 5. Uninstall each Add/Remove Programs entry (only if its key backup is verified)
    foreach ($fortiClientEntry in $Inventory.UninstallEntries) {
        if (-not $script:VerifiedRegistryBackups.ContainsKey($fortiClientEntry.NativeKeyPath)) {
            Write-RemovalLog " SKIPPED uninstall (no verified backup): $($fortiClientEntry.DisplayName)"
            continue
        }
        $uninstallCommand = if ($fortiClientEntry.QuietUninstallString) { $fortiClientEntry.QuietUninstallString } else { $fortiClientEntry.UninstallString }

        if ($fortiClientEntry.ProductCodeOrKeyName -match '^\{[0-9A-Fa-f\-]{36}\}$') {
            $msiLogPath   = Join-Path $PSScriptRoot ("msi_uninstall_{0}_{1}.log" -f ($fortiClientEntry.ProductCodeOrKeyName -replace '[{}]', ''), $runStamp)
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

    # 6. Leftover registry keys
    foreach ($installerRecord in $Inventory.InstallerRecords) {
        Remove-RegistryKeySafely -RegistryPathInput $installerRecord.PSPath -RemovalReason 'Installer Products record'
    }
    foreach ($userDataKey in $Inventory.UserDataKeys) {
        Remove-RegistryKeySafely -RegistryPathInput $userDataKey -RemovalReason 'UserData product record'
    }
    foreach ($upgradeCodeValue in $Inventory.UpgradeCodeValues) {
        Remove-UpgradeCodeValueSafely -NativeKeyPath $upgradeCodeValue.NativeKeyPath -ValueName $upgradeCodeValue.ValueName
    }
    foreach ($fortiClientEntry in $Inventory.UninstallEntries) {
        if (Test-Path -LiteralPath "Registry::$($fortiClientEntry.NativeKeyPath)") {
            Remove-RegistryKeySafely -RegistryPathInput $fortiClientEntry.NativeKeyPath -RemovalReason 'Add/Remove Programs key'
        }
    }
    foreach ($loadedUserKey in $Inventory.LoadedUserKeys) {
        Remove-RegistryKeySafely -RegistryPathInput $loadedUserKey -RemovalReason 'loaded user hive'
    }

    # 7. Shortcuts (always removed)
    foreach ($shortcutPath in $Inventory.Shortcuts) {
        Remove-PathWithFallback -TargetPath $shortcutPath -ItemKind 'shortcut'
    }

    # 8. Install and data folders (always removed)
    foreach ($fortinetFolderPath in $fortinetFolderPaths) {
        Remove-PathWithFallback -TargetPath $fortinetFolderPath -ItemKind 'folder'
    }

    Write-RemovalLog "===== $passLabel PASS END ====="
}

# ============================ MAIN ============================

Write-RemovalLog "Run started. Backup folder: $backupRunDirectory"
$removalInventory = Get-RemovalInventory

if (-not (Backup-AllTargetsVerified -Inventory $removalInventory)) {
    Write-RemovalLog "Aborting: a machine-wide registry backup failed. Nothing was changed."
    return
}

Invoke-RemovalPass -IsDryRun $true -Inventory $removalInventory

Write-Host ""
Write-Host "Dry run complete. Review the log and manifest before continuing."
Write-Host "Log: $removalLogFilePath"
Write-Host "Manifest: $manifestFilePath"
$typedConfirmation = Read-Host "Type DELETE (case sensitive) to remove the items listed above, or anything else to stop"
if ($typedConfirmation -cne 'DELETE') {
    Write-RemovalLog "Stopped by operator after dry run. Nothing was removed."
    return
}

Invoke-RemovalPass -IsDryRun $false -Inventory $removalInventory

Write-RemovalLog "Verification"
$remainingServices = Get-FortiServices
$remainingTasks    = Get-FortiScheduledTasks
$remainingRunValues = Get-FortiRunValues
$remainingShortcuts = Get-FortiShortcuts
$remainingFolders  = @($fortinetFolderPaths | Where-Object { Test-Path -LiteralPath $_ })
$remainingUninstallEntries = @()
foreach ($uninstallRootPath in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
    if (-not (Test-Path $uninstallRootPath)) { continue }
    foreach ($uninstallKey in (Get-ChildItem $uninstallRootPath)) {
        if ((Get-ItemProperty $uninstallKey.PSPath).DisplayName -like '*FortiClient*') { $remainingUninstallEntries += $uninstallKey }
    }
}
Write-RemovalLog "Remaining services: $($remainingServices.Count), scheduled tasks: $($remainingTasks.Count), Run values: $($remainingRunValues.Count), shortcuts: $($remainingShortcuts.Count), folders: $($remainingFolders.Count), Add/Remove entries: $($remainingUninstallEntries.Count)"
Write-RemovalLog "Items scheduled for deletion at reboot: $($script:DelayedDeleteCount)"
Write-RemovalLog "Signed-out profiles were not modified."
if (($script:DelayedDeleteCount -gt 0) -or $remainingFolders.Count -gt 0) {
    Write-RemovalLog "REBOOT REQUIRED to finish removing locked files. Log: $removalLogFilePath"
} else {
    Write-RemovalLog "Done. Reboot before reinstalling. Log: $removalLogFilePath"
}