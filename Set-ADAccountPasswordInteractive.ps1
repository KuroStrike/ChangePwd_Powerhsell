<#
.SYNOPSIS
    Interactively changes the password of an Active Directory account, with
    confirmation, validation, logging and -WhatIf support.

.DESCRIPTION
    Prompts for the target sAMAccountName, the current password and the new
    password (twice). Verifies the account exists, confirms the two new-password
    entries match before contacting the directory, and calls
    Set-ADAccountPassword. Supports -WhatIf / -Confirm via SupportsShouldProcess.

    Sample / reference script. Test against a lab or non-production account
    first. Requires the ActiveDirectory module (RSAT) and rights to change the
    target account's password.

.PARAMETER SamAccountName
    The sAMAccountName of the account to change. Prompted if not supplied.

.PARAMETER LogPath
    File to append operation logs to. Defaults to <script>_log.txt beside the
    script. Passwords are never written to the log.

.EXAMPLE
    .\Set-ADAccountPasswordInteractive.ps1 -SamAccountName svc-backup

.EXAMPLE
    .\Set-ADAccountPasswordInteractive.ps1 -SamAccountName svc-backup -WhatIf

.NOTES
    Author : KuroStrike
    License: MIT
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string] $SamAccountName,

    [Parameter(Mandatory = $false)]
    [string] $LogPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -------------------- Logging --------------------
if (-not $LogPath) {
    $scriptName = [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)
    $LogPath = Join-Path (Split-Path -Parent $PSCommandPath) "$scriptName`_log.txt"
}

function Write-Log {
    param(
        [Parameter(Mandatory)] [string] $Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')] [string] $Level = 'INFO'
    )
    $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -Path $LogPath -Value $line
    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        default { Write-Verbose $line }
    }
}

# -------------------- Prerequisites --------------------
function Assert-Module {
    param([Parameter(Mandatory)] [string] $Name)
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        throw "Module '$Name' not found. Install the RSAT component that provides it."
    }
}

# Compare two SecureStrings without leaving plaintext in a managed string.
# The decrypted buffers are zeroed and freed in the finally block.
function Test-SecureStringMatch {
    param(
        [Parameter(Mandatory)] [System.Security.SecureString] $First,
        [Parameter(Mandatory)] [System.Security.SecureString] $Second
    )
    if ($First.Length -ne $Second.Length) { return $false }

    $bstr1 = [IntPtr]::Zero
    $bstr2 = [IntPtr]::Zero
    try {
        $bstr1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($First)
        $bstr2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Second)
        $p1 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr1)
        $p2 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr2)
        return [string]::Equals($p1, $p2, [StringComparison]::Ordinal)
    }
    finally {
        $p1 = $null; $p2 = $null
        if ($bstr1 -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr1) }
        if ($bstr2 -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr2) }
    }
}

# -------------------- Main --------------------
try {
    Assert-Module -Name 'ActiveDirectory'
    Import-Module ActiveDirectory -ErrorAction Stop

    if (-not $SamAccountName) {
        $SamAccountName = Read-Host 'Enter the sAMAccountName of the account to change'
    }
    if ([string]::IsNullOrWhiteSpace($SamAccountName)) {
        throw 'No account name provided.'
    }

    # Confirm the account exists (and get its DN for the log / ShouldProcess target).
    $account = Get-ADUser -Filter 'SamAccountName -eq $SamAccountName' -Properties DistinguishedName
    if (-not $account) {
        Write-Log -Level 'ERROR' -Message "Account '$SamAccountName' not found."
        throw "Account '$SamAccountName' does not exist."
    }

    $currentPassword = Read-Host 'Enter the CURRENT password' -AsSecureString
    $newPassword     = Read-Host 'Enter the NEW password' -AsSecureString
    $confirmPassword = Read-Host 'Confirm the NEW password' -AsSecureString

    if (-not (Test-SecureStringMatch -First $newPassword -Second $confirmPassword)) {
        Write-Log -Level 'WARN' -Message "New-password confirmation mismatch for '$SamAccountName'. Aborted."
        throw 'The new password and its confirmation do not match. No change was made.'
    }

    if ($PSCmdlet.ShouldProcess($account.DistinguishedName, 'Set-ADAccountPassword')) {
        Set-ADAccountPassword -Identity $account.DistinguishedName `
            -OldPassword $currentPassword -NewPassword $newPassword -ErrorAction Stop
        Write-Log -Level 'INFO' -Message "Password changed successfully for '$SamAccountName'."
        Write-Host "Password changed successfully for '$SamAccountName'." -ForegroundColor Green
    }
    else {
        Write-Log -Level 'INFO' -Message "WhatIf/declined: no change made for '$SamAccountName'."
    }
}
catch {
    Write-Log -Level 'ERROR' -Message ("Failure for '{0}': {1}" -f $SamAccountName, $_.Exception.Message)
    throw
}
finally {
    foreach ($s in 'currentPassword', 'newPassword', 'confirmPassword') {
        if (Get-Variable -Name $s -Scope 0 -ErrorAction SilentlyContinue) {
            $val = Get-Variable -Name $s -ValueOnly
            if ($val -is [System.Security.SecureString]) { $val.Dispose() }
            Set-Variable -Name $s -Value $null
        }
    }
}
