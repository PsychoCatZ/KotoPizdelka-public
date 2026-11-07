#requires -Version 5.1
# Run as the normal Windows user, not an administrator/different account.
[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_.@-]*$')][string]$SshHost = 'relay-host',
    [string]$BackupDirectory = "$env:LOCALAPPDATA\KotoPizdelka\RelayBackups"
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows is required.' }
if ($BackupDirectory.Contains('"')) { throw 'Invalid backup directory.' }
$source = Join-Path $PSScriptRoot 'Pull-RelayBackup.ps1'
# A real first transfer must succeed before installing any scheduled task.
& powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $source -SshHost $SshHost -BackupDirectory $BackupDirectory
if ($LASTEXITCODE -ne 0) { throw 'First verified backup failed. No scheduled task was installed.' }
$tools = Join-Path $env:LOCALAPPDATA 'KotoPizdelka\BackupTools'
$ancestor = [IO.DirectoryInfo]$tools
while ($null -ne $ancestor) {
    if ($ancestor.Exists -and ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unsafe tools path.' }
    $ancestor = $ancestor.Parent
}
[void][IO.Directory]::CreateDirectory($tools)
if ((Get-Item -LiteralPath $tools).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Unsafe tools directory.' }
$acl = Get-Acl -LiteralPath $BackupDirectory
Set-Acl -LiteralPath $tools -AclObject $acl
$installed = Join-Path $tools 'Pull-RelayBackup.ps1'
Copy-Item -LiteralPath $source -Destination $installed -Force
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$name = 'KotoPizdelka-RelayBackup-' + $sid
$existing = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
if ($existing -and $existing.Principal.UserId -ne $sid -and $existing.Principal.UserId -ne [Security.Principal.WindowsIdentity]::GetCurrent().Name) {
    throw 'A task with this name belongs to a different user.'
}
$arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $installed + '" -SshHost "' + $SshHost + '" -BackupDirectory "' + [IO.Path]::GetFullPath($BackupDirectory) + '"'
$action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument $arguments
$hourly = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(3) -RepetitionInterval (New-TimeSpan -Hours 1)
$logon = New-ScheduledTaskTrigger -AtLogOn -User $sid
$principal = New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 15) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $name -Action $action -Trigger @($hourly, $logon) -Principal $principal -Settings $settings -Description 'Pull and DPAPI-encrypt verified KotoPizdelka relay backup over existing SSH.' -Force | Out-Null
Write-Output 'Installed: hourly pull and pull at logon. Windows must be running and this user logged in.'
Write-Output ('Backups: ' + [IO.Path]::GetFullPath($BackupDirectory))
Write-Output 'DPAPI recovery requires this Windows user profile. Do not delete/reinstall it before decrypting copies.'
