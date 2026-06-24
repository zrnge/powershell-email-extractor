<#
.SYNOPSIS
    Extracts attachments from .eml files without external libraries.
    Compatible with Windows PowerShell 5.1 (e.g. Windows Sandbox).

.DESCRIPTION
    Recursively walks MIME structure, decodes base64 / quoted-printable,
    handles RFC 2231 filenames, sanitizes attacker-controlled names, and
    emits SHA-256 + magic-byte triage records for each extracted file.

.EXAMPLE
    .\Extract-EmlAttachments.ps1 -EmlPath "C:\Mail\message.eml"

.EXAMPLE
    .\Extract-EmlAttachments.ps1 -Folder "C:\Mail" -SavePath "C:\Attachments" -IncludeInline
#>

[CmdletBinding(DefaultParameterSetName = 'File')]
param(
    [Parameter(Mandatory, ParameterSetName = 'File')]
    [string]$EmlPath,

    [Parameter(Mandatory, ParameterSetName = 'Folder')]
    [string]$Folder,

    [string]$SavePath = "C:\Attachments",
    [switch]$IncludeInline,
    [string]$CsvLog
)

# ---------- helpers ----------

function Decode-Rfc2231 {
    param([string]$Value)
    # strip optional charset'lang' prefix from filename*=UTF-8''%xx form
    if ($Value -match "^([^']*)'([^']*)'(.*)$") { $Value = $matches[3] }
    [regex]::Replace($Value, '%([0-9A-Fa-f]{2})', {
        param($m) [char][Convert]::ToInt32($m.Groups[1].Value, 16)
    })
}

function Get-PartFileName {
    param([string]$Headers)
    # RFC 2231 split form: filename*0= / filename*1= ...
    $split = [regex]::Matches($Headers, '(?im)(?:file)?name\*(\d+)\*?="?([^"\r\n;]+)"?') |
             Sort-Object { [int]$_.Groups[1].Value }
    if ($split.Count -gt 0) {
        return (Decode-Rfc2231 (-join ($split | ForEach-Object { $_.Groups[2].Value })))
    }
    if ($Headers -match '(?im)(?:file)?name\*="?([^"\r\n;]+)"?') { return Decode-Rfc2231 $matches[1] }
    if ($Headers -match '(?im)filename="?([^"\r\n;]+)"?')        { return $matches[1] }
    if ($Headers -match '(?im)\bname="?([^"\r\n;]+)"?')          { return $matches[1] }
    return $null
}

function Get-SafeName {
    param([string]$Name)
    $n = [System.IO.Path]::GetFileName($Name.Trim())
    $n = $n -replace '[<>:"/\\|?*]', '_'
    if ($n -match '^(CON|PRN|AUX|NUL|COM\d|LPT\d)(\.|$)') { $n = "_$n" }
    if ($n.Length -gt 200) { $n = $n.Substring(0, 200) }
    if ([string]::IsNullOrWhiteSpace($n)) { $n = "unnamed_$([guid]::NewGuid().ToString('N').Substring(0,8))" }
    return $n
}

function Get-UniquePath {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $Path }
    $dir  = Split-Path $Path
    $stem = [System.IO.Path]::GetFileNameWithoutExtension($Path)
    $ext  = [System.IO.Path]::GetExtension($Path)
    $i = 1
    do {
        $candidate = Join-Path $dir ("{0}_{1}{2}" -f $stem, $i, $ext)
        $i++
    } while (Test-Path -LiteralPath $candidate)
    return $candidate
}

# ---------- recursive MIME walk ----------

function Walk-Mime {
    param([string]$Chunk, [string]$Base, [string]$Save, [bool]$Inline)

    $idx = $Chunk.IndexOf("`r`n`r`n")
    if ($idx -lt 0) { $idx = $Chunk.IndexOf("`n`n") }
    if ($idx -lt 0) { return }

    $headers = $Chunk.Substring(0, $idx)
    $body    = $Chunk.Substring($idx).TrimStart("`r", "`n")

    # Unfold folded headers (continuation lines start with whitespace) so that
    # boundary= / filename= wrapped across lines are matched. Headers only —
    # the body is left untouched.
    $headers = [regex]::Replace($headers, "`r`n[ `t]+", " ")

    # multipart -> split on this part's boundary and recurse
    if ($headers -match '(?im)Content-Type:\s*multipart/[^\r\n]*?boundary="?([^"\r\n;]+)"?') {
        $b = $matches[1]
        foreach ($sub in ($body -split [regex]::Escape("--$b"))) {
            $t = $sub.Trim()
            if ($t -eq '' -or $t -eq '--') { continue }
            Walk-Mime -Chunk $sub -Base $Base -Save $Save -Inline $Inline
        }
        return
    }

    # message/rfc822 -> the body IS a full nested email. Recurse into it so we
    # reach attachments inside forwarded / quarantine-wrapped messages.
    if ($headers -match '(?im)Content-Type:\s*message/rfc822') {
        Walk-Mime -Chunk $body -Base $Base -Save $Save -Inline $Inline
        return
    }

    # leaf part — keep attachments (and inline if requested). Also keep parts
    # that declare a filename but no Content-Disposition (common in Outlook
    # mail), while still skipping the plain text/html body parts.
    $isAttachment = $headers -match '(?im)Content-Disposition:\s*attachment'
    $isInline     = $headers -match '(?im)Content-Disposition:\s*inline'

    $fileName = Get-PartFileName -Headers $headers

    $ctypeLine = if ($headers -match '(?im)Content-Type:\s*([^\r\n;]+)') { $matches[1].Trim().ToLower() } else { '' }
    $isBodyText = $ctypeLine -eq 'text/plain' -or $ctypeLine -eq 'text/html'

    $keep = $isAttachment -or ($Inline -and $isInline) -or ($fileName -and -not $isBodyText)
    if (-not $keep) { return }

    if (-not $fileName) { return }
    $fileName = Get-SafeName -Name $fileName

    $out = Get-UniquePath (Join-Path $Save ("{0}_{1}" -f $Base, $fileName))

    $enc = "7bit"
    if ($headers -match '(?im)Content-Transfer-Encoding:\s*([^\r\n]+)') { $enc = $matches[1].Trim().ToLower() }

    try {
        switch ($enc) {
            "base64" {
                $bytes = [Convert]::FromBase64String(($body -replace '\s', ''))
                [System.IO.File]::WriteAllBytes($out, $bytes)
            }
            "quoted-printable" {
                $dec = [regex]::Replace($body, '=([0-9A-Fa-f]{2})', {
                    param($m) [char][Convert]::ToInt32($m.Groups[1].Value, 16) }) -replace '=\r?\n', ''
                [System.IO.File]::WriteAllBytes($out, [System.Text.Encoding]::Default.GetBytes($dec))
            }
            default {
                [System.IO.File]::WriteAllBytes($out, [System.Text.Encoding]::ASCII.GetBytes($body))
            }
        }
    } catch {
        Write-Warning "Decode failed for '$fileName' ($enc): $($_.Exception.Message)"
        return
    }

    # triage: hash + magic bytes (don't trust declared type)
    $hash  = (Get-FileHash -LiteralPath $out -Algorithm SHA256).Hash
    $fb    = [System.IO.File]::ReadAllBytes($out) | Select-Object -First 8
    $magic = ($fb | ForEach-Object { $_.ToString("X2") }) -join ' '
    $ctype = if ($headers -match '(?im)Content-Type:\s*([^\r\n;]+)') { $matches[1].Trim() } else { 'unknown' }

    [PSCustomObject]@{
        File         = Split-Path $out -Leaf
        DeclaredType = $ctype
        TransferEnc  = $enc
        MagicBytes   = $magic
        SHA256       = $hash
        Path         = $out
    }
}

# ---------- per-file driver ----------

function Extract-One {
    param([string]$Path, [string]$Save, [bool]$Inline)
    if (-not (Test-Path -LiteralPath $Path)) { Write-Warning "Not found: $Path"; return }
    $raw  = [System.IO.File]::ReadAllBytes($Path)
    $text = [System.Text.Encoding]::ASCII.GetString($raw)

    # Normalize all line endings to CRLF (handles bare-LF and bare-CR .eml files)
    $text = $text -replace "`r`n", "`n"
    $text = $text -replace "`r", "`n"
    $text = $text -replace "`n", "`r`n"

    $base = [System.IO.Path]::GetFileNameWithoutExtension($Path)
    Walk-Mime -Chunk $text -Base $base -Save $Save -Inline $Inline
}

# ---------- main ----------

if (-not (Test-Path -LiteralPath $SavePath)) { New-Item -ItemType Directory -Path $SavePath | Out-Null }

$results = @()
if ($PSCmdlet.ParameterSetName -eq 'Folder') {
    Get-ChildItem -Path $Folder -Filter *.eml -File | ForEach-Object {
        $results += Extract-One -Path $_.FullName -Save $SavePath -Inline $IncludeInline.IsPresent
    }
} else {
    $results += Extract-One -Path $EmlPath -Save $SavePath -Inline $IncludeInline.IsPresent
}

if ($results) {
    $results | Format-Table -AutoSize
    if ($CsvLog) {
        $results | Export-Csv -Path $CsvLog -NoTypeInformation
        Write-Host "`nTriage log written to $CsvLog"
    }
    Write-Host ("`n{0} attachment(s) extracted to {1}" -f $results.Count, $SavePath)
} else {
    Write-Warning "No attachments extracted. MIME structure dump follows so the layout can be inspected:"
    $dumpTargets = if ($PSCmdlet.ParameterSetName -eq 'Folder') {
        Get-ChildItem -Path $Folder -Filter *.eml -File | Select-Object -ExpandProperty FullName
    } else { @($EmlPath) }

    foreach ($dt in $dumpTargets) {
        if (-not (Test-Path -LiteralPath $dt)) { continue }
        Write-Host "`n--- $dt ---" -ForegroundColor Cyan
        $t = [System.Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($dt))
        $crlf = ([regex]::Matches($t, "`r`n")).Count
        $lf   = ([regex]::Matches($t, "(?<!`r)`n")).Count
        Write-Host ("Size: {0} bytes   CRLF pairs: {1}   bare-LF: {2}" -f $t.Length, $crlf, $lf) -ForegroundColor DarkGray
        [regex]::Matches($t, '(?im)(boundary="?[^"\r\n;]+"?|Content-Type:[^\r\n]+|Content-Disposition:[^\r\n]+|Content-Transfer-Encoding:[^\r\n]+)') |
            ForEach-Object { Write-Host ("  " + $_.Value.Trim()) }
    }
    Write-Host "`nPaste the dump above if the parser still misses an attachment." -ForegroundColor Yellow
}
