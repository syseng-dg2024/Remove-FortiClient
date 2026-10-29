#Requires -RunAsAdministrator

$ErrorActionPreference = 'Continue'
$runStamp           = Get-Date -Format 'yyyyMMdd_HHmmss'
$backupRunDirectory = Join-Path $PSScriptRoot "Backup\Backup_$runStamp"
$registryBackupDirectory = Join-Path $backupRunDirectory 'Registry'
$fileBackupDirectory     = Join-Path $backupRunDirectory 'Files'
$manifestFilePath   = Join-Path $backupRunDirectory 'manifest.csv'
$removalLogFilePath = Join-Path $PSScriptRoot "removal_$runStamp.log"
New-Item -ItemType Directory -Path $registryBackupDirectory, $fileBackupDirectory -Force | Out-Null

$fortinetFolderPaths = @(
    'C:\Program Files\Fortinet',
    'C:\Program Files (x86)\Fortinet',
    'C:\ProgramData\Fortinet'
)

$script:IsDryRunPass            = $true
$script:VerifiedRegistryBackups = @{}   # native key path -> verified backup file
$script:VerifiedFolderBackups   = @{}   # source folder -> verified backup folder
$script:ManifestRows            = New-Object System.Collections.Generic.List[object]
$script:RegistryBackupCounter   = 0

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

# Only these key shapes may ever be deleted. Anything else is refused.
$allowedNativeRemovalPatterns = @(
    '^HKEY_USERS\\[^\\]+\\Software\\Fortinet$',
    '^HKEY_USERS\\[^\\]+\\Software\\Microsoft\\Installer\\Products\\[^\\]+$',
    '^HKEY_USERS\\[^\\]+\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\[^\\]+$',
    '^HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Installer\\Products\\[^\\]+$',
    '^HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Installer\\UserData\\[^\\]+\\Products\\[^\\]+$',
    '^HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\[^\\]+$',
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

    # E. Loaded user hives only (HKEY_USERS\<SID>)
    $loadedUserKeys = @()
    foreach ($hiveKey in (Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue)) {
        if ($hiveKey.PSChildName -notmatch '^S-1-5-21-') { continue }
        $loadedUserKeys += Get-FortiClientKeysInLoadedUserHive -UserHiveProviderPath "Registry::HKEY_USERS\$($hiveKey.PSChildName)"
    }

    # F. Signed-out profiles (report only, never mounted)
    $signedOutProfiles = @(Get-CimInstance -ClassName Win32_UserProfile -Filter "Special=False AND Loaded=False" -ErrorAction SilentlyContinue |
        Where-Object { $_.SID -like 'S-1-5-21-*' })

    Write-RemovalLog "Inventory:"
    Write-RemovalLog " Add/Remove Programs entries: $($uninstallEntries.Count)"
    foreach ($uninstallEntry in $uninstallEntries) { Write-RemovalLog "   - $($uninstallEntry.DisplayName) $($uninstallEntry.DisplayVersion) [$($uninstallEntry.ProductCodeOrKeyName)]" }
    Write-RemovalLog " Installer Products records: $($installerRecords.Count)"
    Write-RemovalLog " UserData product records: $($userDataKeys.Count)"
    Write-RemovalLog " UpgradeCodes values: $($upgradeCodeValues.Count)"
    Write-RemovalLog " Loaded user hive FortiClient keys: $($loadedUserKeys.Count)"
    foreach ($loadedUserKey in $loadedUserKeys) { Write-RemovalLog "   - $loadedUserKey" }
    Write-RemovalLog " Signed-out profiles (not mounted, not touched): $($signedOutProfiles.Count)"
    foreach ($signedOutProfile in $signedOutProfiles) { Write-RemovalLog "   - $($signedOutProfile.SID) $($signedOutProfile.LocalPath)" }

    return [pscustomobject]@{
        UninstallEntries = $uninstallEntries
        InstallerRecords = $installerRecords
        UserDataKeys     = $userDataKeys
        UpgradeCodeValues = $upgradeCodeValues
        LoadedUserKeys   = $loadedUserKeys
        SignedOutProfiles = $signedOutProfiles
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

# Copies a folder with robocopy, then verifies every file by SHA256 hash, one manifest row per file.
function Backup-FolderVerified {
    param([string]$SourceFolder)
    $folderBackupName  = $SourceFolder -replace '[^A-Za-z0-9]', '_'
    $destinationFolder = Join-Path $fileBackupDirectory $folderBackupName

    robocopy.exe $SourceFolder $destinationFolder /E /COPY:DAT /R:1 /W:1 /NP /NFL /NDL /NJH /NJS | Out-Null
    if ($LASTEXITCODE -ge 8) {
        Add-ManifestRow 'Folder' $SourceFolder $destinationFolder 0 $false "robocopy failed, exit code $LASTEXITCODE"
        return $false
    }

    $sourceFiles = @(Get-ChildItem -LiteralPath $SourceFolder -Recurse -File -Force -ErrorAction SilentlyContinue)
    $allFilesVerified = $true
    $totalBytes = 0
    foreach ($sourceFile in $sourceFiles) {
        $relativePath   = $sourceFile.FullName.Substring($SourceFolder.Length).TrimStart('\')
        $backupFilePath = Join-Path $destinationFolder $relativePath
        $backupExists  = Test-Path -LiteralPath $backupFilePath
        $backupSize    = if ($backupExists) { (Get-Item -LiteralPath $backupFilePath).Length } else { 0 }
        $hashMatches   = $backupExists -and (
            (Get-FileHash -LiteralPath $sourceFile.FullName -Algorithm SHA256).Hash -eq
            (Get-FileHash -LiteralPath $backupFilePath -Algorithm SHA256).Hash
        )
        $fileNote = if ($sourceFile.Length -eq 0) { 'source file is 0 bytes' } else { '' }
        if (-not $hashMatches) { $allFilesVerified = $false }
        $totalBytes += $sourceFile.Length
        Add-ManifestRow 'File' $sourceFile.FullName $backupFilePath $backupSize $hashMatches $fileNote
    }

    $backupFileCount = @(Get-ChildItem -LiteralPath $destinationFolder -Recurse -File -Force -ErrorAction SilentlyContinue).Count
    $folderVerified = $allFilesVerified -and ($backupFileCount -eq $sourceFiles.Count)
    Add-ManifestRow 'Folder' $SourceFolder $destinationFolder $totalBytes $folderVerified "$($sourceFiles.Count) files, $backupFileCount in backup"
    if ($folderVerified) { $script:VerifiedFolderBackups[$SourceFolder] = $destinationFolder }
    return $folderVerified
}

# Backs up and verifies every item the removal would touch. Returns $false if the machine-wide backup fails.
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

    # Every individual key the removal would delete or depend on
    $keysToBackup = @()
    foreach ($uninstallEntry in $Inventory.UninstallEntries) { $keysToBackup += $uninstallEntry.NativeKeyPath }
    foreach ($installerRecord in $Inventory.InstallerRecords) { $keysToBackup += (ConvertTo-NativeRegistryPath $installerRecord.PSPath) }
    foreach ($userDataKey in $Inventory.UserDataKeys) { $keysToBackup += $userDataKey }
    foreach ($loadedUserKey in $Inventory.LoadedUserKeys) { $keysToBackup += $loadedUserKey }
    foreach ($upgradeCodeValue in $Inventory.UpgradeCodeValues) { $keysToBackup += $upgradeCodeValue.NativeKeyPath }

    foreach ($nativeKeyPath in ($keysToBackup | Where-Object { $_ } | Select-Object -Unique)) {
        $keyVerified = Export-RegistryKeyVerified -NativePath $nativeKeyPath
        Write-RemovalLog " $(if ($keyVerified) { 'verified' } else { 'FAILED' }) key: $nativeKeyPath"
    }

    # Every Fortinet folder that exists
    foreach ($fortinetFolderPath in $fortinetFolderPaths) {
        if (-not (Test-Path -LiteralPath $fortinetFolderPath)) { continue }
        $folderVerified = Backup-FolderVerified -SourceFolder $fortinetFolderPath
        Write-RemovalLog " $(if ($folderVerified) { 'verified' } else { 'FAILED' }) folder: $fortinetFolderPath"
    }

    $manifestRows = $script:ManifestRows
    $manifestRows | Export-Csv -LiteralPath $manifestFilePath -NoTypeInformation -Encoding UTF8
    $verifiedCount = @($manifestRows | Where-Object { $_.Verified }).Count
    $failedCount   = @($manifestRows | Where-Object { -not $_.Verified }).Count
    Write-RemovalLog "Manifest written: $manifestFilePath ($verifiedCount verified, $failedCount failed or skipped)"
    return $true
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
        Write-RemovalLog " FAILED: $nativePath ($RemovalReason): $_"
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
    Remove-ItemProperty -LiteralPath "Registry::$NativeKeyPath" -Name $ValueName -ErrorAction SilentlyContinue
    Write-RemovalLog " REMOVED UpgradeCodes value $ValueName under $NativeKeyPath"
}

# One pass over the inventory. Dry pass changes nothing. Live pass makes the changes.
function Invoke-RemovalPass {
    param([bool]$IsDryRun, $Inventory)
    $script:IsDryRunPass = $IsDryRun
    $passLabel = if ($IsDryRun) { 'DRY RUN' } else { 'LIVE' }
    Write-RemovalLog "===== $passLabel PASS START ====="

    # 1. Stop services and processes
    foreach ($fortiService in (Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'Forti*' -or $_.DisplayName -like '*Forti*' })) {
        if ($IsDryRun) { Write-RemovalLog " WOULD STOP service $($fortiService.Name)" }
        else { Write-RemovalLog " stopping service $($fortiService.Name)"; Stop-Service -Name $fortiService.Name -Force -ErrorAction SilentlyContinue }
    }
    foreach ($fortiProcess in (Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -like '*\Fortinet\*' })) {
        if ($IsDryRun) { Write-RemovalLog " WOULD STOP process $($fortiProcess.Name)" }
        else { Write-RemovalLog " stopping process $($fortiProcess.Name)"; Stop-Process -Id $fortiProcess.Id -Force -ErrorAction SilentlyContinue }
    }

    # 2. Uninstall each Add/Remove Programs entry (only if its key backup is verified)
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

    # 3. Machine-wide leftover keys
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

    # 4. Loaded user hives
    foreach ($loadedUserKey in $Inventory.LoadedUserKeys) {
        Remove-RegistryKeySafely -RegistryPathInput $loadedUserKey -RemovalReason 'loaded user hive'
    }

    # 5. Install and data folders (only if their file backup is verified)
    foreach ($fortinetFolderPath in $fortinetFolderPaths) {
        if (-not (Test-Path -LiteralPath $fortinetFolderPath)) { continue }
        if (-not $script:VerifiedFolderBackups.ContainsKey($fortinetFolderPath)) {
            Write-RemovalLog " SKIPPED folder (no verified backup): $fortinetFolderPath"
            continue
        }
        if ($IsDryRun) { Write-RemovalLog " WOULD REMOVE folder $fortinetFolderPath, backup: $($script:VerifiedFolderBackups[$fortinetFolderPath])"; continue }
        Remove-Item -LiteralPath $fortinetFolderPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-RemovalLog " REMOVED folder $fortinetFolderPath"
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
$remainingUninstallEntries = @()
foreach ($uninstallRootPath in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
    if (-not (Test-Path $uninstallRootPath)) { continue }
    foreach ($uninstallKey in (Get-ChildItem $uninstallRootPath)) {
        if ((Get-ItemProperty $uninstallKey.PSPath).DisplayName -like '*FortiClient*') { $remainingUninstallEntries += $uninstallKey }
    }
}
Write-RemovalLog "Remaining machine-wide Add/Remove entries: $($remainingUninstallEntries.Count)"
Write-RemovalLog "Signed-out profiles were not modified."
Write-RemovalLog "Done. Reboot before reinstalling. Log: $removalLogFilePath"