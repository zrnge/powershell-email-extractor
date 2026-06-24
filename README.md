# Extract-EmlAttachments

Extract attachments from `.eml` files with **pure PowerShell** — no external libraries, no NuGet. Built for Windows PowerShell 5.1 (works in Windows Sandbox) and intended for malware/phish triage of saved or quarantined mail.

![Static Badge](https://img.shields.io/badge/Powershell-5.1%2B-darkblue)

## Features

- Recursive MIME parsing (nested `multipart/*` and `message/rfc822` wrappers)
- Decodes `base64` and `quoted-printable`
- Handles RFC 2231 filenames (`name*0=`, `filename*=UTF-8''…`)
- Normalizes line endings and unfolds folded headers
- Sanitizes attacker-controlled filenames (path traversal, reserved names)
- Emits **SHA-256 + magic bytes** per file so you can verify type without opening it

## Usage

```powershell
# single file
.\Extract-EmlAttachments.ps1 -EmlPath "C:\Mail\message.eml" -SavePath "C:\Attachments"

# whole folder, include inline parts, write a triage CSV
.\Extract-EmlAttachments.ps1 -Folder "C:\Mail" -SavePath "C:\Attachments" -IncludeInline -CsvLog "C:\Attachments\_triage.csv"
```

If a script-execution error appears, allow it for the session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```

## Parameters

| Parameter | Description |
|-----------|-------------|
| `-EmlPath` | Path to a single `.eml` file |
| `-Folder` | Process every `.eml` in a folder |
| `-SavePath` | Output directory (default `C:\Attachments`) |
| `-IncludeInline` | Also extract `Content-Disposition: inline` parts |
| `-CsvLog` | Write the triage table (hash, type, magic bytes) to CSV |

If nothing is extracted, the script prints a MIME structure dump to help diagnose the layout.

## ⚠️ Safety

Extracted files may be live malware, especially from quarantine. Run in an isolated VM/sandbox, don't open the output, and check the SHA-256 against threat intel.

## License

MIT
