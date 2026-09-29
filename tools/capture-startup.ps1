[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-zA-Z0-9_-]+$')]
    [string]$Label,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
    [string]$InstallDir
)

$ErrorActionPreference = 'Stop'
$startedAt = Get-Date
$stamp = $startedAt.ToString('yyyyMMdd-HHmmss')
$outputDir = Join-Path $PSScriptRoot "..\evidence\$stamp-$Label"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

function Get-RelevantProcesses {
    Get-CimInstance Win32_Process |
        Where-Object {
            $_.Name -match '(?i)(division|ubisoft|upc|steam|epic)'
        } |
        Select-Object Name, ProcessId, ParentProcessId, CreationDate, ExecutablePath
}

function Get-RelevantConnections {
    $processes = Get-RelevantProcesses
    $processById = @{}
    foreach ($process in $processes) {
        $processById[[int]$process.ProcessId] = $process.Name
    }

    Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Where-Object { $processById.ContainsKey([int]$_.OwningProcess) } |
        Select-Object `
            @{Name = 'ProcessName'; Expression = { $processById[[int]$_.OwningProcess] }},
            OwningProcess,
            State,
            LocalAddress,
            LocalPort,
            RemoteAddress,
            RemotePort
}

function Export-Snapshot {
    param([Parameter(Mandatory = $true)][string]$Stage)

    Get-RelevantProcesses |
        Export-Csv -NoTypeInformation -Encoding UTF8 `
            (Join-Path $outputDir "processes-$Stage.csv")

    Get-RelevantConnections |
        Export-Csv -NoTypeInformation -Encoding UTF8 `
            (Join-Path $outputDir "connections-$Stage.csv")
}

$executables = Get-ChildItem -LiteralPath $InstallDir -File -Recurse `
    -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -in '.exe', '.dll' }

$normalizedInstallDir = $InstallDir.TrimEnd([IO.Path]::DirectorySeparatorChar) +
    [IO.Path]::DirectorySeparatorChar

$hashes = foreach ($file in $executables) {
    $hash = Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256
    [PSCustomObject]@{
        RelativePath = $file.FullName.Substring($normalizedInstallDir.Length)
        Length = $file.Length
        SHA256 = $hash.Hash
    }
}
$hashes |
    Sort-Object RelativePath |
    Export-Csv -NoTypeInformation -Encoding UTF8 `
        (Join-Path $outputDir 'executables.sha256.csv')

Export-Snapshot -Stage 'before'

Write-Host "Capture directory: $outputDir"
Write-Host 'Launch the game now. Stop at the stable menu or first stable error.'
Read-Host 'Press Enter when the launch attempt is finished'

Export-Snapshot -Stage 'after'
$finishedAt = Get-Date

@(
    "Label: $Label"
    "Started: $($startedAt.ToString('o'))"
    "Finished: $($finishedAt.ToString('o'))"
    "Install directory: $InstallDir"
    "Network profiles at finish:"
    (Get-NetConnectionProfile -ErrorAction SilentlyContinue |
        Select-Object Name, InterfaceAlias, NetworkCategory, IPv4Connectivity,
            IPv6Connectivity |
        Format-Table -AutoSize |
        Out-String)
) | Set-Content -Encoding UTF8 (Join-Path $outputDir 'summary.txt')

Write-Host 'Capture complete. Review the files before sharing them.'
