# Run unseal-psk.ps1 as SYSTEM (the Windows Biometric Service context) via a
# one-off scheduled task, then print the PSK.
#
# Run from an elevated PowerShell on the Windows install that paired the
# reader:
#
#   powershell -ExecutionPolicy Bypass -File unseal-as-system.ps1 -BlobPath C:\path\psk_dpapi_blob.bin
#
# The task and its working files are removed afterwards. The printed PSK is
# the reader's pairing key; treat it like a password.

param(
    [Parameter(Mandatory = $true)][string]$BlobPath
)

$ErrorActionPreference = "Stop"

$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this from an elevated (Administrator) PowerShell; creating a SYSTEM task needs admin rights."
    exit 1
}

# SYSTEM cannot reliably read network shares or user folders, so stage the
# blob and the worker script in a local directory only admins can read.
$work = Join-Path $env:ProgramData "GoodixUnseal"
New-Item -ItemType Directory -Force $work | Out-Null
icacls $work /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null

$blob = Join-Path $work "psk_dpapi_blob.bin"
$worker = Join-Path $work "unseal-psk.ps1"
$result = Join-Path $work "psk.txt"
Copy-Item -Force $BlobPath $blob
Copy-Item -Force (Join-Path $PSScriptRoot "unseal-psk.ps1") $worker
Remove-Item $result -ErrorAction SilentlyContinue

$task = "GoodixUnsealPsk"
$action = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$worker`" -BlobPath `"$blob`" -OutPath `"$result`""
try {
    schtasks /create /tn $task /tr $action /ru SYSTEM /sc once /st 00:00 /f | Out-Null
    schtasks /run /tn $task | Out-Null
    for ($i = 0; $i -lt 30 -and -not (Test-Path $result); $i++) {
        Start-Sleep -Seconds 1
    }
} finally {
    schtasks /delete /tn $task /f 2>$null | Out-Null
}

if (-not (Test-Path $result)) {
    Remove-Item -Recurse -Force $work
    Write-Error "The SYSTEM task produced no result within 30 seconds. Check Task Scheduler history for 'GoodixUnsealPsk'. The reader is unchanged."
    exit 1
}

$output = (Get-Content $result -Raw).Trim()
Remove-Item -Recurse -Force $work
if ($output -like "ERROR:*") {
    Write-Error $output.Substring(7)
    exit 1
}
Write-Output $output
