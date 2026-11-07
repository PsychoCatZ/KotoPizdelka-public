#requires -Version 5.1
# KotoPizdelka relay backup add-on v1. Run as the Windows user owning the backups.
[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_.@-]*$')][string]$SshHost = 'relay-host',
    [string]$BackupDirectory = "$env:LOCALAPPDATA\KotoPizdelka\RelayBackups",
    [switch]$Unprotect,
    [string]$InputFile,
    [string]$OutputFile
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$entropy = [Text.Encoding]::UTF8.GetBytes('KotoPizdelka relay backup v1')
$magic = [Text.Encoding]::ASCII.GetBytes("KOTO-RELAY-DPAPI-1`n")

function Protect-Directory([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    $node = [IO.DirectoryInfo]$full
    while ($null -ne $node) {
        if ($node.Exists -and ($node.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Backup directories cannot contain junctions or symbolic links.'
        }
        $node = $node.Parent
    }
    [void][IO.Directory]::CreateDirectory($full)
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner($sid)
    $acl.SetAccessRuleProtection($true, $false)
    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    foreach ($identity in @($sid, (New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', $inherit, 'None', 'Allow')
        [void]$acl.AddAccessRule($rule)
    }
    (Get-Item -LiteralPath $full).SetAccessControl($acl)
    return $full
}
function Hash-Bytes([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}
function Decode-Backup([byte[]]$Bytes) {
    if ($Bytes.Length -le $magic.Length) { throw 'Invalid backup format.' }
    for ($i = 0; $i -lt $magic.Length; $i++) {
        if ($Bytes[$i] -ne $magic[$i]) { throw 'Invalid backup format.' }
    }
    [byte[]]$payload = New-Object byte[] ($Bytes.Length - $magic.Length)
    [Buffer]::BlockCopy($Bytes, $magic.Length, $payload, 0, $payload.Length)
    return ,([Security.Cryptography.ProtectedData]::Unprotect($payload, $entropy, 'CurrentUser'))
}
function New-PrivateFile([string]$Path, [byte[]]$Bytes) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
}

$temporary = $null
$partial = $null
$guard = $null
try {
    if ($env:OS -ne 'Windows_NT') { throw 'Windows DPAPI is required.' }
    if ($Unprotect) {
        if (-not $InputFile -or -not $OutputFile) { throw 'Specify -InputFile and -OutputFile.' }
        if ((Get-Item -LiteralPath $InputFile).Length -gt 536870912) { throw 'Backup is too large.' }
        $parent = Protect-Directory ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($OutputFile)))
        $target = Join-Path $parent ([IO.Path]::GetFileName($OutputFile))
        [byte[]]$plain = Decode-Backup ([IO.File]::ReadAllBytes($InputFile))
        try { New-PrivateFile $target $plain } finally { [Array]::Clear($plain, 0, $plain.Length) }
        Write-Output "Decrypted recovery archive: $target"
        return
    }
    if ($InputFile -or $OutputFile) { throw '-InputFile/-OutputFile require -Unprotect.' }
    $folder = Protect-Directory $BackupDirectory
    $guard = [IO.File]::Open((Join-Path $folder '.pull.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
    Get-ChildItem -LiteralPath $folder -File | Where-Object { $_.Name -cmatch '^\.(incoming|encrypted)-[0-9a-f]{32}$' } | Remove-Item -Force
    $ssh = (Get-Command ssh.exe -ErrorAction Stop).Source
    $scp = (Get-Command scp.exe -ErrorAction Stop).Source
    $options = @('-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=15',
                 '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3')
    # The server emits only filename, byte length and hash after verification; no keys/tokens.
    $lines = & $ssh @options $SshHost 'sudo -n python3 /opt/kotopizdelka-relay/backup/relay-backup.py latest'
    if ($LASTEXITCODE -ne 0) { throw 'SSH backup verification failed. Check the existing relay-host connection.' }
    $info = ($lines -join "`n") | ConvertFrom-Json
    if ($info.name -cnotmatch '^relay-\d{8}T\d{6}Z-[0-9a-f]{12}\.tar\.gz$' -or
        $info.sha256 -cnotmatch '^[0-9a-f]{64}$' -or $info.bytes -le 0 -or $info.bytes -gt 536870912) {
        throw 'Invalid or oversized server backup response.'
    }
    $destination = Join-Path $folder ($info.name + '.dpapi')
    if ([IO.File]::Exists($destination)) {
        [byte[]]$existing = Decode-Backup ([IO.File]::ReadAllBytes($destination))
        try { if ((Hash-Bytes $existing) -cne $info.sha256) { throw 'Existing local backup checksum differs.' } }
        finally { [Array]::Clear($existing, 0, $existing.Length) }
        @{ checked_utc = [DateTime]::UtcNow.ToString('o'); archive = $info.name; sha256 = $info.sha256 } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $folder 'last-success.json') -Encoding UTF8
        Write-Output "Already verified: $($info.name)"
        return
    }
    $temporary = Join-Path $folder ('.incoming-' + [Guid]::NewGuid().ToString('N'))
    $partial = Join-Path $folder ('.encrypted-' + [Guid]::NewGuid().ToString('N'))
    $remote = $SshHost + ':/var/backups/kotopizdelka-relay/' + $info.name
    & $scp @options '-B' '-q' $remote $temporary
    if ($LASTEXITCODE -ne 0) { throw 'SCP download failed; previous backups were retained.' }
    if ((Get-Item -LiteralPath $temporary).Length -ne $info.bytes) { throw 'Downloaded length differs.' }
    [byte[]]$bytes = [IO.File]::ReadAllBytes($temporary)
    try {
        if ((Hash-Bytes $bytes) -cne $info.sha256) { throw 'Downloaded checksum differs.' }
        [byte[]]$protected = [Security.Cryptography.ProtectedData]::Protect($bytes, $entropy, 'CurrentUser')
        [byte[]]$envelope = New-Object byte[] ($magic.Length + $protected.Length)
        [Buffer]::BlockCopy($magic, 0, $envelope, 0, $magic.Length)
        [Buffer]::BlockCopy($protected, 0, $envelope, $magic.Length, $protected.Length)
        New-PrivateFile $partial $envelope
        [byte[]]$restored = Decode-Backup ([IO.File]::ReadAllBytes($partial))
        try { if ((Hash-Bytes $restored) -cne $info.sha256) { throw 'Encrypted backup round-trip failed.' } }
        finally { [Array]::Clear($restored, 0, $restored.Length) }
    } finally { [Array]::Clear($bytes, 0, $bytes.Length) }
    [IO.File]::Move($partial, $destination)
    $partial = $null
    # Keep 48 recent snapshots plus one per last 14 distinct UTC backup dates.
    $archives = @(Get-ChildItem -LiteralPath $folder -File | Where-Object { $_.Name -cmatch '^relay-\d{8}T\d{6}Z-[0-9a-f]{12}\.tar\.gz\.dpapi$' } | Sort-Object Name -Descending)
    $keep = @{}; $days = @{}
    for ($i = 0; $i -lt $archives.Count; $i++) {
        $file = $archives[$i]; $day = $file.Name.Substring(6, 8)
        if ($i -lt 48) { $keep[$file.Name] = $true }
        if (-not $days.ContainsKey($day) -and $days.Count -lt 14) { $days[$day] = $true; $keep[$file.Name] = $true }
    }
    foreach ($file in $archives) {
        if (-not $keep.ContainsKey($file.Name)) { Remove-Item -LiteralPath $file.FullName -Force }
    }
    $status = @{ checked_utc = [DateTime]::UtcNow.ToString('o'); archive = $info.name; sha256 = $info.sha256 }
    $status | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $folder 'last-success.json') -Encoding UTF8
    Write-Output "Downloaded, encrypted and verified: $($info.name)"
} catch {
    Write-Error 'Relay backup failed. Check SSH, available disk space and Windows account. Keep completed copies.' -ErrorAction Continue
    exit 1
} finally {
    if ($temporary -and [IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    if ($partial -and [IO.File]::Exists($partial)) { [IO.File]::Delete($partial) }
    if ($guard) { $guard.Dispose() }
}
