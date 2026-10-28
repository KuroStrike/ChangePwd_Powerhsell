# ChangePwd_Powershell

Interactive PowerShell script to change the password of an Active Directory
account — with confirmation matching, validation, logging and `-WhatIf` support.

Sample / reference code. Test against a lab or non-production account first.

## Requirements

- Windows PowerShell 5.1+ or PowerShell 7
- RSAT: the `ActiveDirectory` module
- Rights to change the target account's password

## Usage

```powershell
# Interactive
.\Set-ADAccountPasswordInteractive.ps1 -SamAccountName svc-backup

# Dry run — validates and matches, makes no change
.\Set-ADAccountPasswordInteractive.ps1 -SamAccountName svc-backup -WhatIf
```

The script prompts for the current password and the new password (entered
twice), confirms the two new entries match **before** contacting the directory,
then calls `Set-ADAccountPassword`.

## Notes

- Passwords are read as `SecureString` and are never written to the log.
- The new-password confirmation is compared, and the decrypted buffers are zeroed
  and freed; the `SecureString` objects are disposed in a `finally` block.
- Supports `-WhatIf` / `-Confirm` (`SupportsShouldProcess`).

## License

MIT — see [LICENSE](LICENSE).
