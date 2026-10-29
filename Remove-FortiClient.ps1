#Requires -RunAsAdministrator

$ErrorActionPreference = 'Continue'
$runStamp      = Get-Date -Format 'yyyyMMdd_HHmmss'
$backupRoot    = Join-Path $PSScriptRoot "Backup\Backup_$runStamp"
$regBackupDir  = Join-Path $backupRoot 'Registry'
$taskBackupDir = Join-Path $backupRoot 'ScheduledTasks'
$fileBackupDir = Join-Path $backupRoot 'Files'
$manifestPath  = Join-Path $backupRoot 'manifest.csv'
$logPath       = Join-Path $PSScriptRoot "removal_$runStamp.log"
New-Item -ItemType Directory -Path $regBackupDir, $taskBackupDir, (Join-Path $fileBackupDir 'Shortcuts') -Force | Out-Null

$fortinetFolders = @('C:\Program Files\Fortinet', 'C:\Program Files (x86)\Fortinet', 'C:\ProgramData\Fortinet')

# ---- Every registry location, defined once. Everything below reads from these two tables. ----
# Machine-wide paths are relative to HKEY_LOCAL_MACHINE\
$machineRegistry = [ordered]@{
    Fortinet          = 'SOFTWARE\Fortinet'
    InstallerProducts = 'SOFTWARE\Classes\Installer\Products'
    UserData          = 'SOFTWARE\Classes\Installer\UserData'
    UpgradeCodes      = 'SOFTWARE\Classes\Installer\UpgradeCodes'
    Uninstall64       = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    Uninstall32       = 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    Run               = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    RunOnce           = 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    Run32             = 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    RunOnce32         = 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
}

# Per-user paths are relative to HKEY_USERS\<SID>\
$userRegistry = [ordered]@{
    Fortinet          = 'Software\Fortinet'
    InstallerProducts = 'Software\Microsoft\Installer\Products'
    Uninstall         = 'Software\Microsoft\Windows\CurrentVersion\Uninstall'
    Run               = 'Software\Microsoft\Windows\CurrentVersion\Run'
    RunOnce           = 'Software\Microsoft\Windows\CurrentVersion\RunOnce'
}

$script:IsDryRun      = $true
$script:VerifiedKeys  = @{}
$script:VerifiedTasks = @{}
$script:ManifestRows  = New-Object System.Collections.Generic.List[object]
$script:RegCounter    = 0
$script:RebootQueued  = 0

if (-not ('FortiCleanup.NativeFile' -as [type])) {
    Add-Type -Namespace FortiCleanup -Name NativeFile -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
'@
}

function Write-Log {
    param([string]$Message)
    $line = "[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'), $Message
    Write-Host $line
    Add-Content -LiteralPath $logPath -Value $line
}

function Add-ManifestRow {
    param([string]$Type, [string]$Source, [string]$Backup, [long]$Size, [bool]$Verified, [string]$Note = '')
    $script:ManifestRows.Add([pscustomobject]@{
        Time = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'); Type = $Type; Source = $Source
        Backup = $Backup; SizeBytes = $Size; Verified = $Verified; Note = $Note
    })
}

function ConvertTo-NativeKey {
    param([string]$Path)
    $p = $Path -replace '^Microsoft\.PowerShell\.Core\\', ''
    $p = $p -replace '^Registry::', ''
    $p = $p -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\'
    return $p
}

function Get-MachineProvider { param([string]$Name) return "HKLM:\$($machineRegistry[$Name])" }
function Get-MachineNative   { param([string]$Name) return "HKEY_LOCAL_MACHINE\$($machineRegistry[$Name])" }

# Allowed: children of any machine location, the exact Fortinet/Run/RunOnce roots, and children of per-user locations.
function Test-AllowedKey {
    param([string]$Key)
    foreach ($name in $machineRegistry.Keys) {
        $root = Get-MachineNative $name
        if ($Key.Equals($root, [StringComparison]::OrdinalIgnoreCase) -and (($name -like 'Run*') -or ($name -eq 'Fortinet'))) { return $true }
        if ($Key.StartsWith("$root\", [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    foreach ($rel in $userRegistry.Values) {
        $pattern = '^HKEY_USERS\\S-1-5-21-[^\\]+\\' + [regex]::Escape($rel) + '(\\|$)'
        if ($Key -match $pattern) { return $true }
    }
    return $false
}

# Read-only inventory of everything the removal would touch.
function Get-Inventory {
    Write-Log "Building inventory (read only)"

    $uninstallEntries = @()
    foreach ($name in ($machineRegistry.Keys | Where-Object { $_ -like 'Uninstall*' })) {
        $root = Get-MachineProvider $name
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($entry in (Get-ChildItem -LiteralPath $root)) {
            $props = Get-ItemProperty -LiteralPath $entry.PSPath
            if ($props.DisplayName -like '*FortiClient*') {
                $uninstallEntries += [pscustomobject]@{
                    Key = ConvertTo-NativeKey $entry.PSPath; Name = $entry.PSChildName; DisplayName = $props.DisplayName
                    Quiet = $props.QuietUninstallString; Uninstall = $props.UninstallString
                }
            }
        }
    }

    $packedCodes = @(); $installerKeys = @()
    $productsRoot = Get-MachineProvider 'InstallerProducts'
    if (Test-Path -LiteralPath $productsRoot) {
        foreach ($rec in (Get-ChildItem -LiteralPath $productsRoot)) {
            if ((Get-ItemProperty -LiteralPath $rec.PSPath -ErrorAction SilentlyContinue).ProductName -like '*FortiClient*') {
                $installerKeys += ConvertTo-NativeKey $rec.PSPath
                $packedCodes += $rec.PSChildName
            }
        }
    }

    $userDataKeys = @()
    $userDataRoot = Get-MachineProvider 'UserData'
    if (Test-Path -LiteralPath $userDataRoot) {
        foreach ($sid in (Get-ChildItem -LiteralPath $userDataRoot)) {
            $productsPath = Join-Path $sid.PSPath 'Products'
            if (-not (Test-Path -LiteralPath $productsPath)) { continue }
            foreach ($prod in (Get-ChildItem -LiteralPath $productsPath)) {
                $infoName = (Get-ItemProperty -LiteralPath (Join-Path $prod.PSPath 'InstallProperties') -ErrorAction SilentlyContinue).DisplayName
                if (($infoName -like '*FortiClient*') -or ($packedCodes -contains $prod.PSChildName)) {
                    $userDataKeys += ConvertTo-NativeKey $prod.PSPath
                }
            }
        }
    }

    $upgradeValues = @()
    $upgradeRoot = Get-MachineProvider 'UpgradeCodes'
    if (Test-Path -LiteralPath $upgradeRoot) {
        foreach ($uc in (Get-ChildItem -LiteralPath $upgradeRoot)) {
            $valueNames = (Get-Item -LiteralPath $uc.PSPath).GetValueNames()
            foreach ($code in $packedCodes) {
                if ($valueNames -contains $code) { $upgradeValues += [pscustomobject]@{ Key = ConvertTo-NativeKey $uc.PSPath; Name = $code } }
            }
        }
    }

    # Machine-wide FortiClient settings root (HKLM\SOFTWARE\Fortinet)
    $machineFortinetKey = $null
    if (Test-Path -LiteralPath (Get-MachineProvider 'Fortinet')) { $machineFortinetKey = Get-MachineNative 'Fortinet' }

    # Run roots: machine-wide, then loaded user hives only (signed-out profiles are never mounted)
    $runRoots = @($machineRegistry.Keys | Where-Object { $_ -like 'Run*' } | ForEach-Object { Get-MachineProvider $_ })
    $userKeys = @()
    foreach ($hive in (Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue)) {
        if ($hive.PSChildName -notmatch '^S-1-5-21-') { continue }
        foreach ($name in $userRegistry.Keys) {
            $root = "Registry::HKEY_USERS\$($hive.PSChildName)\$($userRegistry[$name])"
            if ($name -like 'Run*') { $runRoots += $root; continue }
            if (-not (Test-Path -LiteralPath $root)) { continue }
            if ($name -eq 'Fortinet') { $userKeys += ConvertTo-NativeKey $root; continue }
            foreach ($k in (Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
                $kp = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
                if (($kp.ProductName -like '*FortiClient*') -or ($kp.DisplayName -like '*FortiClient*')) { $userKeys += ConvertTo-NativeKey $k.PSPath }
            }
        }
    }

    $runValues = @()
    foreach ($root in $runRoots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($prop in (Get-ItemProperty -LiteralPath $root).PSObject.Properties) {
            if ($prop.Name -like 'PS*') { continue }
            $data = [string]$prop.Value
            if (($prop.Name -like '*Forti*') -or ($data -like '*Fortinet*')) {
                $runValues += [pscustomobject]@{ Key = ConvertTo-NativeKey $root; Name = $prop.Name; Data = $data }
            }
        }
    }

    # Per-profile AppData Fortinet folders (files only, no registry hive mounting)
    $profileFolders = @()
    foreach ($user in (Get-ChildItem -LiteralPath 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue)) {
        foreach ($sub in @('AppData\Local\Fortinet', 'AppData\Roaming\Fortinet')) {
            $candidate = Join-Path $user.FullName $sub
            if (Test-Path -LiteralPath $candidate) { $profileFolders += $candidate }
        }
    }

    $services = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -like 'Forti*' -or $_.Name -like 'FA_*' -or $_.Name -like 'FCT_*' -or $_.PathName -like '*\Fortinet\*'
    })
    $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $_.TaskName -like '*Forti*' -or @($_.Actions | Where-Object { $_.Execute -like '*Fortinet*' }).Count -gt 0
    })

    $shortcutFolders = @('C:\Users\Public\Desktop', 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs')
    foreach ($user in (Get-ChildItem -LiteralPath 'C:\Users' -Directory -Force -ErrorAction SilentlyContinue)) {
        $shortcutFolders += "$($user.FullName)\Desktop"
        $shortcutFolders += "$($user.FullName)\OneDrive\Desktop"
        $shortcutFolders += "$($user.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs"
    }
    $shortcuts = @()
    foreach ($folder in $shortcutFolders) {
        if (-not (Test-Path -LiteralPath $folder)) { continue }
        $shortcuts += @(Get-ChildItem -LiteralPath $folder -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*Forti*' } | ForEach-Object { $_.FullName })
    }

    $signedOut = @(Get-CimInstance -ClassName Win32_UserProfile -Filter "Special=False AND Loaded=False" -ErrorAction SilentlyContinue | Where-Object { $_.SID -like 'S-1-5-21-*' })

    Write-Log "Inventory: Add/Remove entries $($uninstallEntries.Count), Installer records $($installerKeys.Count), UserData $($userDataKeys.Count), UpgradeCodes $($upgradeValues.Count), machine FortiClient root $(if ($machineFortinetKey) { 'yes' } else { 'no' }), per-user keys $($userKeys.Count), Run values $($runValues.Count), profile AppData folders $($profileFolders.Count), services $($services.Count), tasks $($tasks.Count), shortcuts $($shortcuts.Count)"
    foreach ($entry in $uninstallEntries) { Write-Log "   - $($entry.DisplayName) [$($entry.Name)]" }
    foreach ($svc in $services) { Write-Log "   - service $($svc.Name) ($($svc.State), $($svc.StartMode))" }
    foreach ($pf in $profileFolders) { Write-Log "   - profile folder $pf" }
    Write-Log "Signed-out profiles (registry not mounted; AppData folders still cleaned): $($signedOut.Count)"

    return [pscustomobject]@{
        Uninstall = $uninstallEntries; InstallerKeys = $installerKeys; UserDataKeys = $userDataKeys
        UpgradeValues = $upgradeValues; MachineFortinet = $machineFortinetKey; UserKeys = $userKeys
        RunValues = $runValues; ProfileFolders = $profileFolders
        Services = $services; Tasks = $tasks; Shortcuts = $shortcuts
    }
}

# Exports one registry key and verifies the .reg file. Returns $true only if verified.
function Export-KeyBackup {
    param([string]$Key)
    if (-not (Test-AllowedKey $Key)) { Add-ManifestRow 'Registry' $Key '' 0 $false 'refused: not allowlisted'; return $false }
    $script:RegCounter++
    $regKey   = $Key -replace '^HKEY_LOCAL_MACHINE', 'HKLM' -replace '^HKEY_USERS', 'HKU'
    $safeName = $Key -replace '[^A-Za-z0-9]', '_'
    if ($safeName.Length -gt 120) { $safeName = $safeName.Substring(0, 120) }
    $file = Join-Path $regBackupDir ("{0:D4}_{1}.reg" -f $script:RegCounter, $safeName)

    reg.exe export $regKey $file /y | Out-Null
    $exported = ($LASTEXITCODE -eq 0) -and (Test-Path -LiteralPath $file)
    $size = if ($exported) { (Get-Item -LiteralPath $file).Length } else { 0 }
    $verified = $exported -and ($size -gt 0) -and ((Get-Content -LiteralPath $file -TotalCount 1) -like '*Windows Registry Editor*')
    Add-ManifestRow 'Registry' $Key $file $size $verified
    if ($verified) { $script:VerifiedKeys[$Key] = $file }
    return $verified
}

# Backs up everything first. Returns $false (nothing removed) if a machine-wide export fails.
function Backup-All {
    param($Inv)
    Write-Log "Backing up and verifying everything the removal would touch"

    foreach ($name in $machineRegistry.Keys) {
        $nativeRoot = "HKLM\$($machineRegistry[$name])"
        reg.exe query $nativeRoot | Out-Null
        if ($LASTEXITCODE -ne 0) { Write-Log " not present: $nativeRoot"; continue }
        $file = Join-Path $regBackupDir "$name.reg"
        reg.exe export $nativeRoot $file /y | Out-Null
        $size = if (Test-Path -LiteralPath $file) { (Get-Item -LiteralPath $file).Length } else { 0 }
        $ok = ($LASTEXITCODE -eq 0) -and ($size -gt 0)
        Add-ManifestRow 'Registry' $nativeRoot $file $size $ok 'whole tree'
        Write-Log " $(if ($ok) { 'verified' } else { 'FAILED' }): $nativeRoot"
        if (-not $ok) { return $false }
    }

    $keys = @()
    $keys += $Inv.Uninstall | ForEach-Object { $_.Key }
    $keys += $Inv.InstallerKeys
    $keys += $Inv.UserDataKeys
    $keys += $Inv.UpgradeValues | ForEach-Object { $_.Key }
    $keys += $Inv.MachineFortinet
    $keys += $Inv.UserKeys
    $keys += $Inv.RunValues | ForEach-Object { $_.Key }
    foreach ($key in ($keys | Where-Object { $_ } | Select-Object -Unique)) {
        $ok = Export-KeyBackup $key
        Write-Log " $(if ($ok) { 'verified' } else { 'FAILED' }) key: $key"
    }

    foreach ($task in $Inv.Tasks) {
        $taskKey = "$($task.TaskPath)$($task.TaskName)"
        $file = Join-Path $taskBackupDir (($taskKey -replace '[^A-Za-z0-9]', '_') + '.xml')
        try {
            $xml = Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop
            Set-Content -LiteralPath $file -Value $xml -Encoding UTF8
        } catch { Write-Log " task export error: $($_.Exception.Message)" }
        $size = if (Test-Path -LiteralPath $file) { (Get-Item -LiteralPath $file).Length } else { 0 }
        $taskOk = ($size -gt 0) -and [bool](Select-String -LiteralPath $file -Pattern '<Task' -Quiet)
        Add-ManifestRow 'ScheduledTask' $taskKey $file $size $taskOk
        if ($taskOk) { $script:VerifiedTasks[$taskKey] = $file }
        Write-Log " $(if ($taskOk) { 'verified' } else { 'FAILED' }) task: $taskKey"
    }

    # Shortcuts and folders are best effort: a failed copy does not block removal.
    $index = 0
    foreach ($shortcut in $Inv.Shortcuts) {
        $index++
        $dest = Join-Path $fileBackupDir ("Shortcuts\{0:D3}_{1}" -f $index, ((Split-Path -Leaf $shortcut) -replace '[^A-Za-z0-9._-]', '_'))
        Copy-Item -LiteralPath $shortcut -Destination $dest -Recurse -Force -ErrorAction SilentlyContinue
        Add-ManifestRow 'Shortcut' $shortcut $dest 0 (Test-Path -LiteralPath $dest) 'best effort'
    }
    foreach ($folder in ($fortinetFolders + $Inv.ProfileFolders)) {
        if (-not (Test-Path -LiteralPath $folder)) { continue }
        $dest = Join-Path $fileBackupDir ($folder -replace '[^A-Za-z0-9]', '_')
        robocopy.exe $folder $dest /E /COPY:DAT /R:1 /W:1 /NP /NFL /NDL /NJH /NJS | Out-Null
        Add-ManifestRow 'Folder' $folder $dest 0 ($LASTEXITCODE -lt 8) 'best effort'
        Write-Log " file backup (best effort, robocopy exit $LASTEXITCODE): $folder"
    }

    $script:ManifestRows | Export-Csv -LiteralPath $manifestPath -NoTypeInformation -Encoding UTF8
    Write-Log "Manifest written: $manifestPath"
    return $true
}

function Add-RebootDelete {
    param([string]$Path)
    if ([FortiCleanup.NativeFile]::MoveFileEx($Path, $null, 4)) { $script:RebootQueued++ }
    else { Write-Log " could not schedule for reboot: $Path" }
}

function Remove-PathSafe {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    if ($script:IsDryRun) { Write-Log " WOULD REMOVE $Path"; return }

    Remove-Item -LiteralPath $Path -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
    if (-not (Test-Path -LiteralPath $Path)) { Write-Log " REMOVED $Path"; return }

    # Still present: delete what can be deleted (deepest first), queue the rest for reboot
    $items = @(Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue | Sort-Object { $_.FullName.Length } -Descending)
    foreach ($item in $items) {
        if ($item.PSIsContainer -and @(Get-ChildItem -LiteralPath $item.FullName -Force -ErrorAction SilentlyContinue).Count -gt 0) {
            Add-RebootDelete $item.FullName
            continue
        }
        try { Remove-Item -LiteralPath $item.FullName -Force -Confirm:$false -ErrorAction Stop }
        catch { Write-Log " locked: $($item.FullName) ($($_.Exception.Message))"; Add-RebootDelete $item.FullName }
    }
    Remove-Item -LiteralPath $Path -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $Path) { Add-RebootDelete $Path; Write-Log " scheduled for reboot: $Path" }
    else { Write-Log " REMOVED $Path" }
}

function Remove-RegKey {
    param([string]$Key, [string]$Reason)
    if (-not (Test-AllowedKey $Key)) { Write-Log " REFUSED (not allowlisted): $Key"; return }
    if (-not (Test-Path -LiteralPath "Registry::$Key")) { return }
    if (-not $script:VerifiedKeys.ContainsKey($Key)) { Write-Log " SKIPPED (no verified backup): $Key"; return }
    if ($script:IsDryRun) { Write-Log " WOULD REMOVE key: $Key ($Reason)"; return }
    try {
        Remove-Item -LiteralPath "Registry::$Key" -Recurse -Force -Confirm:$false -ErrorAction Stop
        Write-Log " REMOVED key: $Key ($Reason)"
    } catch { Write-Log " FAILED key: $Key : $($_.Exception.Message)" }
}

function Remove-RegValue {
    param([string]$Key, [string]$Name)
    if (-not (Test-AllowedKey $Key)) { Write-Log " REFUSED (not allowlisted): $Key"; return }
    if (-not $script:VerifiedKeys.ContainsKey($Key)) { Write-Log " SKIPPED value (no verified backup): $Key [$Name]"; return }
    if ($script:IsDryRun) { Write-Log " WOULD REMOVE value $Name under $Key"; return }
    try {
        Remove-ItemProperty -LiteralPath "Registry::$Key" -Name $Name -ErrorAction Stop
        Write-Log " REMOVED value $Name under $Key"
    } catch { Write-Log " FAILED value $Name under $Key : $($_.Exception.Message)" }
}

function Remove-FortiTask {
    param($Task)
    $key = "$($Task.TaskPath)$($Task.TaskName)"
    if (-not $script:VerifiedTasks.ContainsKey($key)) { Write-Log " SKIPPED task (no verified backup): $key"; return }
    if ($script:IsDryRun) { Write-Log " WOULD REMOVE task: $key"; return }
    try {
        Unregister-ScheduledTask -TaskName $Task.TaskName -TaskPath $Task.TaskPath -Confirm:$false -ErrorAction Stop
        Write-Log " REMOVED task: $key"
    } catch { Write-Log " FAILED task: $key : $($_.Exception.Message)" }
}

function Stop-FortiProcesses {
    $passes = if ($script:IsDryRun) { 1 } else { 3 }
    for ($pass = 1; $pass -le $passes; $pass++) {
        $procs = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -like '*\Fortinet\*' })
        if ($procs.Count -eq 0) { break }
        foreach ($proc in $procs) {
            if ($script:IsDryRun) { Write-Log " WOULD STOP process $($proc.Name)" }
            else { Write-Log " stopping process $($proc.Name)"; Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
        }
        if (-not $script:IsDryRun) { Start-Sleep -Seconds 2 }
    }
}

# Runs the Add/Remove Programs uninstall(s) first. Returns $false unless every one returns 0 or 1605.
function Invoke-Uninstall {
    param($Inv)
    $allOk = $true
    foreach ($entry in $Inv.Uninstall) {
        if (-not $script:VerifiedKeys.ContainsKey($entry.Key)) {
            Write-Log " uninstall blocked (no verified backup): $($entry.DisplayName)"; $allOk = $false; continue
        }
        $cmd = if ($entry.Quiet) { $entry.Quiet } else { $entry.Uninstall }

        if ($entry.Name -match '^\{[0-9A-Fa-f-]{36}\}$') {
            $msiLog  = Join-Path $PSScriptRoot ("msi_uninstall_{0}_{1}.log" -f ($entry.Name -replace '[{}]', ''), $runStamp)
            $msiArgs = "/x $($entry.Name) /qn /norestart /l*v `"$msiLog`""
            if ($script:IsDryRun) { Write-Log " WOULD RUN: msiexec.exe $msiArgs"; continue }
            Write-Log " running: msiexec.exe $msiArgs"
            $proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArgs -PassThru
        }
        elseif ($cmd) {
            if ($script:IsDryRun) { Write-Log " WOULD RUN: $cmd"; continue }
            Write-Log " running: $cmd"
            $proc = Start-Process -FilePath 'cmd.exe' -ArgumentList "/c `"$cmd`"" -PassThru
        }
        else {
            Write-Log " no uninstall command for $($entry.DisplayName)"; $allOk = $false; continue
        }

        if (-not $proc.WaitForExit(900000)) {
            $proc.Kill()
            Write-Log " timed out after 15 minutes, killed"; $allOk = $false; continue
        }
        Write-Log " exit code: $($proc.ExitCode)"
        if ($proc.ExitCode -notin @(0, 1605)) { $allOk = $false }
    }
    return $allOk
}

# Removes everything else. Only runs after the uninstall has succeeded.
function Invoke-Cleanup {
    param($Inv)
    foreach ($svc in $Inv.Services) {
        if ($script:IsDryRun) { Write-Log " WOULD DISABLE and STOP service $($svc.Name)"; continue }
        Write-Log " disabling and stopping service $($svc.Name)"
        Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
    }
    Stop-FortiProcesses
    foreach ($task in $Inv.Tasks) { Remove-FortiTask -Task $task }
    foreach ($rv in $Inv.RunValues) { Remove-RegValue -Key $rv.Key -Name $rv.Name }
    Stop-FortiProcesses

    foreach ($key in $Inv.InstallerKeys) { Remove-RegKey -Key $key -Reason 'Installer Products record' }
    foreach ($key in $Inv.UserDataKeys)  { Remove-RegKey -Key $key -Reason 'UserData record' }
    foreach ($v in $Inv.UpgradeValues)   { Remove-RegValue -Key $v.Key -Name $v.Name }
    foreach ($entry in $Inv.Uninstall)   { Remove-RegKey -Key $entry.Key -Reason 'Add/Remove Programs key' }
    if ($Inv.MachineFortinet)            { Remove-RegKey -Key $Inv.MachineFortinet -Reason 'machine-wide FortiClient settings' }
    foreach ($key in $Inv.UserKeys)      { Remove-RegKey -Key $key -Reason 'per-user FortiClient record' }

    foreach ($shortcut in $Inv.Shortcuts)                     { Remove-PathSafe -Path $shortcut }
    foreach ($folder in ($fortinetFolders + $Inv.ProfileFolders)) { Remove-PathSafe -Path $folder }
}

function Show-Summary {
    param($Inv)
    $services = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'Forti*' -or $_.Name -like 'FA_*' -or $_.Name -like 'FCT_*' })
    $tasks    = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like '*Forti*' })
    $folders  = @(($fortinetFolders + $Inv.ProfileFolders) | Where-Object { Test-Path -LiteralPath $_ })
    Write-Log "Remaining: services $($services.Count), tasks $($tasks.Count), folders $($folders.Count). Queued for reboot: $($script:RebootQueued)"
    if (($script:RebootQueued -gt 0) -or ($folders.Count -gt 0)) { Write-Log "REBOOT REQUIRED to finish removing locked files." }
    else { Write-Log "Done. Signed-out profiles' registry hives were not modified." }
}

# ============================ MAIN ============================

Write-Log "Run started. Backup: $backupRoot"
$inventory = Get-Inventory
if (-not (Backup-All -Inv $inventory)) {
    Write-Log "ABORTED: machine-wide registry backup failed. Nothing was changed."
    return
}

$script:IsDryRun = $true
Invoke-Uninstall -Inv $inventory | Out-Null
Invoke-Cleanup -Inv $inventory

Write-Host ""
Write-Host "Dry run complete. Review the log: $logPath"
$answer = Read-Host "Type DELETE (case sensitive) to proceed, or anything else to stop"
if ($answer -cne 'DELETE') { Write-Log "Stopped by operator. Nothing was removed."; return }

$script:IsDryRun = $false
if (-not (Invoke-Uninstall -Inv $inventory)) {
    Write-Log "ABORTED: MSI uninstall did not return 0 or 1605. Nothing else was changed. Reboot, then rerun."
    return
}
Invoke-Cleanup -Inv $inventory
Show-Summary -Inv $inventory