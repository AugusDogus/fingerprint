# Decrypt the reader's DPAPI-encrypted PSK blob (TLV 0xbb010002).
#
# The Windows Biometric Service seals the blob with DPAPI in its own context,
# so this only succeeds when run as SYSTEM on the Windows install that paired
# the reader. Use unseal-as-system.ps1 to run it that way.
#
# Writes the 32-byte PSK as hex to -OutPath. That file is the pairing key:
# copy it off the machine and delete it.

param(
    [Parameter(Mandatory = $true)][string]$BlobPath,
    [Parameter(Mandatory = $true)][string]$OutPath
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Security

$blob = [System.IO.File]::ReadAllBytes($BlobPath)
$who = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$errors = @()

foreach ($scope in @("CurrentUser", "LocalMachine")) {
    try {
        $plain = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $blob, $null,
            [System.Security.Cryptography.DataProtectionScope]::$scope)
        if ($plain.Length -ne 32) {
            $errors += "${scope}: decrypted to $($plain.Length) bytes, expected 32"
            continue
        }
        $hex = ($plain | ForEach-Object { $_.ToString("x2") }) -join ""
        Set-Content -Path $OutPath -Value $hex -Encoding ascii
        exit 0
    } catch {
        $errors += "${scope}: $($_.Exception.Message)"
    }
}

$message = "Could not decrypt $BlobPath as $who. " +
    "Run this as SYSTEM on the Windows install that paired the reader. " +
    "Details: " + ($errors -join "; ")
Set-Content -Path $OutPath -Value "ERROR: $message" -Encoding ascii
exit 1
