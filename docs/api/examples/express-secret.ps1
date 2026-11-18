#Requires -Version 7.4
<#
.SYNOPSIS
  Create and read TransTeira express secrets from a script (since 2.3).

.DESCRIPTION
  PowerShell 7.4 or later (.NET 8), no module: AesGcm, HKDF, SHA256 and RandomNumberGenerator
  from System.Security.Cryptography, Invoke-RestMethod for the HTTP calls. The format is
  docs/architecture/e2e-format.md section 3.3.9 (express profile of the one-time secrets: no
  passphrase, no file, link composed by the client); the self-test mode checks this file against
  internal/tte2/testdata/vectors.json.

  Modes:
    create [-TextFile FILE]    create an express secret, print its link
    seal [-TextFile FILE]      print the createExpressSecret body and the key (JSON)
    status                     print the state of a link (consumes nothing)
    read [-PassThru]           reveal a secret (once) and print its text
    self-test -Vectors FILE    check the format against the vectors

  The text comes from -TextFile or from redirected standard input, never from the command line
  (other users of the host can read the process list). It is used as is, as UTF-8, with no
  trimming, and must hold 1 to 10 000 Unicode code points. The link of status and read comes
  from the file named by TT_LINK_FILE or, without it, from redirected standard input.

  read writes the text to the standard output of the process: the exact UTF-8 bytes when it is
  redirected (pwsh -File express-secret.ps1 read > file), or the text with its control and
  bidirectional characters replaced when it is a terminal. In a PowerShell session, -PassThru
  returns the exact text as a string instead ($text = ./express-secret.ps1 read -PassThru); it
  is then yours not to display it raw.

  Environment:
    TT_URL         tenant URL, e.g. https://transfer.entity-a.example.com (create)
    TT_TOKEN_FILE  file holding an API token of the entity allowed to create express secrets
                   (expressAllowed); without it the creation is anonymous (create)
    TT_EXPIRES     1h, 1d or 7d (default 1d) (create, seal)
    TT_LINK_FILE   status, read: file holding the link (default: redirected standard input)
  The certificates are checked against the system store (add the CA of an internal PKI there).

  The link https://<fqdn>/s/<token>#k=<key> is the secret: create prints it on standard output
  only, never in a log; write it to a private place. A new key is drawn for every secret, never
  reused, not even to retry a failed creation. The server never receives the text nor the key.

  seal prints {"fragmentKey": "...", "body": {...}}, where body is the complete request body of
  POST /api/v1/express-secrets (encryptedText, verifier, keyVerifier, expiresIn).

.EXAMPLE
  $env:TT_URL = 'https://transfer.entity-a.example.com'
  $env:TT_TOKEN_FILE = "$HOME/.config/transteira/token"   # optional: anonymous without it
  $env:TT_EXPIRES = '1h'
  $linkFile = New-TemporaryFile                             # created readable by you only
  ./express-secret.ps1 create -TextFile ./db-password.txt | Set-Content -LiteralPath $linkFile

.EXAMPLE
  $env:TT_LINK_FILE = $linkFile.FullName
  ./express-secret.ps1 status
  $text = ./express-secret.ps1 read -PassThru
  Remove-Item -LiteralPath $linkFile
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory, Position = 0)]
  [ValidateSet('create', 'seal', 'status', 'read', 'self-test')]
  [string]$Mode,
  [string]$TextFile,
  [string]$Vectors,
  [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$KeySize = 32
$NonceSize = 12
$TagSize = 16
$SealedOverhead = 1 + $NonceSize + $TagSize                         # 29 bytes
$MaxSecretRunes = 10000
$MaxSecretEncodedSize = ($SealedOverhead + 4 * $MaxSecretRunes) / 3 * 4  # 53 372
$InfoSecret = 'transteira/tte2/v1/secret'
$InfoKeyProof = 'transteira/tte2/v1/secret/key-proof'
$InfoText = 'transteira/tte2/v1/secret/text'
$InfoProof = 'transteira/tte2/v1/secret/proof'
$SecretAad = [Text.Encoding]::ASCII.GetBytes('TTE2S')
$Durations = @('1h', '1d', '7d')
$LinkPattern = '^(https://[^/?#@\s]+)/s/(tts_[A-Za-z0-9]{43})(?:#k=([A-Za-z0-9_-]{43}))?$'
# Characters that could drive or deceive a terminal: C0 controls, DEL and C1 controls (escape
# sequences), and the bidirectional formatting characters (they could reorder what is shown).
# Replaced in every message (line breaks included), since an error can quote a problem of the
# server named by the link, which may be hostile.
$Unprintable = '[\x00-\x1F\x7F-\x9F\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]'
# Replaced before a revealed text is shown on a terminal: the same characters except tab, line
# feed and a carriage return right before a line feed (a lone carriage return would send the
# cursor back to the start of the line and let the rest of the line overwrite what was shown).
$TerminalUnsafe = '\r(?!\n)|[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]'
# What status prints: an RFC 3339 date, and a reason of secret-gone that is a plain word (read,
# expired, deleted, locked, or one a later server may add).
$Rfc3339 = '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$'
$ReasonWord = '^[a-z][a-z0-9_-]{0,31}$'
# Strict UTF-8: invalid bytes and lone surrogates throw instead of being replaced.
$Utf8 = [Text.UTF8Encoding]::new($false, $true)
$Sha256 = [Security.Cryptography.HashAlgorithmName]::SHA256

# A format error, named after the Go error of internal/tte2 (e.g. ErrAuth).
class FormatError : Exception {
  [string]$Code
  FormatError([string]$code, [string]$detail) : base("${code}: $detail") { $this.Code = $code }
}

# A non-2xx answer: the operation, the status and the problem (RFC 9457).
class ApiError : Exception {
  [string]$Op
  [int]$Status
  [string]$Code
  [string]$Reason
  [string]$RetryAfter
  ApiError([string]$op, [int]$status, [string]$code, [string]$detail, [string]$reason, [string]$retryAfter) :
  base("${op}: $status $code $detail".TrimEnd()) {
    $this.Op = $op; $this.Status = $status; $this.Code = $code; $this.Reason = $reason
    $this.RetryAfter = $retryAfter
  }
}

# --- Encodings -------------------------------------------------------------------------------

function ConvertTo-Hex([byte[]]$b) { [Convert]::ToHexString($b).ToLowerInvariant() }

function ConvertTo-Base64Url([byte[]]$b) {
  [Convert]::ToBase64String($b).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

# Strict base64url: alphabet only, no padding, canonical; $null otherwise.
function ConvertFrom-Base64Url([string]$s) {
  if ($s -cnotmatch '^[A-Za-z0-9_-]*$' -or $s.Length % 4 -eq 1) { return $null }
  $std = $s.Replace('-', '+').Replace('_', '/')
  $std += '=' * ((4 - $std.Length % 4) % 4)
  [byte[]]$b = [Convert]::FromBase64String($std)
  if ((ConvertTo-Base64Url $b) -cne $s) { return $null }
  return , $b
}

# The key of a link fragment: 43 canonical base64url characters, 32 bytes.
function ConvertFrom-FragmentKey([string]$s) {
  $k = if ($s.Length -eq 43) { ConvertFrom-Base64Url $s } else { $null }
  if ($null -eq $k) { throw [FormatError]::new('ErrInvalidKey', 'not 43 canonical base64url characters') }
  return , $k
}

function Get-RandomBytes([int]$n) { , [Security.Cryptography.RandomNumberGenerator]::GetBytes($n) }

# Number of Unicode code points of a well-formed string (a surrogate pair counts once).
function Get-RuneCount([string]$s) {
  $n = 0
  foreach ($c in $s.ToCharArray()) { if (-not [char]::IsLowSurrogate($c)) { $n++ } }
  $n
}

# --- Derivations (sections 3.3.2, 3.3.4 and 3.3.9) -------------------------------------------

# HKDF-SHA-256 of 32 bytes with an empty salt.
function Get-Hkdf([byte[]]$ikm, [string]$info) {
  , [Security.Cryptography.HKDF]::DeriveKey($Sha256, $ikm, $KeySize, [byte[]]@(), $Utf8.GetBytes($info))
}

# K' = HKDF(K, salt = empty, "transteira/tte2/v1/secret"): an express secret has no passphrase.
function Get-RootKey([byte[]]$key) {
  if ($key.Length -ne $KeySize) { throw [FormatError]::new('ErrInvalidKey', "$($key.Length) bytes") }
  , (Get-Hkdf $key $InfoSecret)
}

function Get-KeyProof([byte[]]$key) { , (Get-Hkdf $key $InfoKeyProof) }
function Get-Proof([byte[]]$rootKey) { , (Get-Hkdf $rootKey $InfoProof) }
function Get-Verifier([byte[]]$proof) { , [Security.Cryptography.SHA256]::HashData($proof) }

# --- Text (section 3.3.3) --------------------------------------------------------------------

function Test-TextLength([string]$text) {
  if ((Get-RuneCount $text) -gt $MaxSecretRunes) {
    throw [FormatError]::new('ErrInvalidSecret', "longer than $MaxSecretRunes characters")
  }
}

# Seals the text: base64url(0x01 || nonce || AES-256-GCM(text, AAD "TTE2S") || tag).
function Protect-SecretText([byte[]]$rootKey, [string]$text, [byte[]]$nonce = (Get-RandomBytes $NonceSize)) {
  try { $plain = $Utf8.GetBytes($text) } catch { throw [FormatError]::new('ErrInvalidSecret', 'lone surrogate') }
  Test-TextLength $text
  $blob = [byte[]]::new($SealedOverhead + $plain.Length)
  $blob[0] = 1
  [Array]::Copy($nonce, 0, $blob, 1, $NonceSize)
  $ct = [byte[]]::new($plain.Length)
  $tag = [byte[]]::new($TagSize)
  $aes = [Security.Cryptography.AesGcm]::new((Get-Hkdf $rootKey $InfoText), $TagSize)
  try { $aes.Encrypt($nonce, $plain, $ct, $tag, $SecretAad) } finally { $aes.Dispose() }
  [Array]::Copy($ct, 0, $blob, 1 + $NonceSize, $ct.Length)
  [Array]::Copy($tag, 0, $blob, 1 + $NonceSize + $ct.Length, $TagSize)
  ConvertTo-Base64Url $blob
}

# Opens a sealed text: strict framing (ErrEncoding), tag (ErrAuth), then the text rules.
function Unprotect-SecretText([byte[]]$rootKey, [string]$sealed) {
  $blob = if ($sealed.Length -le $MaxSecretEncodedSize) { ConvertFrom-Base64Url $sealed } else { $null }
  if ($null -eq $blob -or $blob.Length -lt $SealedOverhead -or $blob[0] -ne 1) {
    throw [FormatError]::new('ErrEncoding', 'not a sealed secret text')
  }
  $n = $blob.Length - $SealedOverhead
  $nonce = [byte[]]$blob[1..$NonceSize]
  $ct = [byte[]]::new($n)
  [Array]::Copy($blob, 1 + $NonceSize, $ct, 0, $n)
  $tag = [byte[]]::new($TagSize)
  [Array]::Copy($blob, 1 + $NonceSize + $n, $tag, 0, $TagSize)
  $plain = [byte[]]::new($n)
  $aes = [Security.Cryptography.AesGcm]::new((Get-Hkdf $rootKey $InfoText), $TagSize)
  try { $aes.Decrypt($nonce, $ct, $tag, $plain, $SecretAad) }
  catch [Security.Cryptography.AuthenticationTagMismatchException] {
    throw [FormatError]::new('ErrAuth', 'wrong key, or altered')
  } finally { $aes.Dispose() }
  # GetString keeps a leading U+FEFF, as in Go.
  try { $text = $Utf8.GetString($plain) } catch { throw [FormatError]::new('ErrInvalidSecret', 'not valid UTF-8') }
  Test-TextLength $text
  $text
}

# --- Creation --------------------------------------------------------------------------------

function Get-Env([string]$name, [string]$default) {
  $v = [Environment]::GetEnvironmentVariable($name)
  if ($v) { return $v }
  if ($PSBoundParameters.ContainsKey('default')) { return $default }
  throw "$name is required"
}

# Reads all of the redirected standard input as bytes (no console decoding).
function Read-StandardInput([string]$what) {
  if (-not [Console]::IsInputRedirected) { throw "$what expected on redirected standard input" }
  $buffer = [IO.MemoryStream]::new()
  $stdin = [Console]::OpenStandardInput()
  try { $stdin.CopyTo($buffer) } finally { $stdin.Dispose() }
  , $buffer.ToArray()
}

# Reads the text, as is, from -TextFile or standard input; invalid UTF-8 is refused.
function Read-Text {
  $raw = if ($TextFile) { [IO.File]::ReadAllBytes($TextFile) } else { Read-StandardInput 'the text (or -TextFile)' }
  try { $Utf8.GetString($raw) } catch { throw 'the text is not valid UTF-8' }
}

# Seals text under a new key and returns the fragment key and the createExpressSecret body. It
# opens its own sealed text before returning, so that the verifiers never certify a text the
# recipient could not open.
function New-SealedSecret([string]$text, [string]$expiresIn) {
  if ($text -eq '') { throw 'empty text: an express secret holds 1 to 10 000 characters' }
  $count = Get-RuneCount $text
  if ($count -gt $MaxSecretRunes) { throw "text of $count characters: at most $MaxSecretRunes" }
  if ($Durations -cnotcontains $expiresIn) { throw "TT_EXPIRES must be 1h, 1d or 7d, not '$expiresIn'" }
  $key = Get-RandomBytes $KeySize   # a new key for every secret, from the CSPRNG
  $rootKey = Get-RootKey $key
  $sealed = Protect-SecretText $rootKey $text
  if ((Unprotect-SecretText $rootKey $sealed) -cne $text) { throw 'self-check failed' }
  [pscustomobject]@{
    FragmentKey = ConvertTo-Base64Url $key
    Body        = [ordered]@{
      encryptedText = $sealed
      verifier      = ConvertTo-Hex (Get-Verifier (Get-Proof $rootKey))
      keyVerifier   = ConvertTo-Hex (Get-Verifier (Get-KeyProof $key))
      expiresIn     = $expiresIn
    }
  }
}

function Get-Prop($o, [string]$name, $default) {
  if ($null -ne $o -and $o -isnot [string] -and $o.PSObject.Properties[$name]) { $o.$name } else { $default }
}

# Calls the API operation $op and returns its answer; a non-2xx answer throws an ApiError with
# the problem (RFC 9457). The error names the operation, not the path, which may hold a secret
# token. Redirects are refused.
function Invoke-Api([string]$op, [string]$method, [string]$uri, [hashtable]$headers = @{}, $body) {
  $params = @{
    Method = $method; Uri = $uri; Headers = $headers + @{ Accept = 'application/json' }
    SkipHttpErrorCheck = $true; StatusCodeVariable = 'status'; ResponseHeadersVariable = 'answerHeaders'
    MaximumRedirection = 0; TimeoutSec = 60
  }
  if ($null -ne $body) {
    $params.ContentType = 'application/json'
    $params.Body = $Utf8.GetBytes(($body | ConvertTo-Json -Depth 5 -Compress))
  }
  $res = Invoke-RestMethod @params
  if ($status -lt 200 -or $status -ge 300) {
    $retryAfter = "$(Get-Prop $res 'retryAfterSeconds' '')"
    if ($answerHeaders -and $answerHeaders.ContainsKey('Retry-After')) { $retryAfter = "$($answerHeaders['Retry-After'])" }
    throw [ApiError]::new($op, $status, (Get-Prop $res 'code' ''), (Get-Prop $res 'detail' ''),
      (Get-Prop $res 'reason' ''), $retryAfter)
  }
  $res
}

function Invoke-Create {
  $base = (Get-Env 'TT_URL').TrimEnd('/')
  if ($base -cnotmatch '^https://[^/?#@\s]+$') { throw 'TT_URL must be https://<fqdn of the entity>, without a path' }
  $headers = @{}
  if ($env:TT_TOKEN_FILE) {
    $token = ([IO.File]::ReadAllText($env:TT_TOKEN_FILE, $Utf8)).Trim()
    if (-not $token) { throw 'TT_TOKEN_FILE is empty' }
    $headers.Authorization = "Bearer $token"
  }
  $sealed = New-SealedSecret (Read-Text) (Get-Env 'TT_EXPIRES' '1d')
  $created = Invoke-Api createExpressSecret Post "$base/api/v1/express-secrets" $headers $sealed.Body
  if ((Get-Prop $created 'token' '') -cnotmatch '^tts_[A-Za-z0-9]{43}$') { throw 'createExpressSecret: unexpected answer' }
  # The client composes the link; the server never sees the fragment. Standard output only.
  "$base/s/$($created.token)#k=$($sealed.FragmentKey)"
}

function Invoke-Seal {
  $sealed = New-SealedSecret (Read-Text) (Get-Env 'TT_EXPIRES' '1d')
  [ordered]@{ fragmentKey = $sealed.FragmentKey; body = $sealed.Body } | ConvertTo-Json -Depth 5 -Compress
}

# --- Status and reading ----------------------------------------------------------------------

# Reads the link from TT_LINK_FILE or redirected standard input, dropping surrounding white
# space; returns the origin, the token and the key ($null when absent and not needed).
function Read-Link([bool]$needKey) {
  $raw = if ($env:TT_LINK_FILE) { [IO.File]::ReadAllBytes($env:TT_LINK_FILE) } else { Read-StandardInput 'the link (or TT_LINK_FILE)' }
  $link = [Text.Encoding]::UTF8.GetString($raw).Trim()
  if ($link -cnotmatch $LinkPattern -or ($needKey -and -not $Matches[3])) {
    $form = if ($needKey) { 'https://<fqdn>/s/<token>#k=<key>' } else { 'https://<fqdn>/s/<token>[#k=<key>]' }
    throw "expected $form in TT_LINK_FILE or on standard input"
  }
  $Matches[1], $Matches[2], $(if ($Matches.ContainsKey(3)) { $Matches[3] } else { $null })
}

# Invoke-RestMethod turns ISO 8601 strings into dates: back to the RFC 3339 form of the API.
# Anything else than a date is refused (the server is the one named by the link).
function Format-Date($v) {
  if ($v -is [datetime]) { return $v.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture) }
  if ($v -is [string] -and $v -cmatch $Rfc3339) { return $v }
  throw 'getSecretLink: unexpected answer'
}

# Prints pending <expiresAt>, read, expired, deleted, locked or closed. Consumes nothing. A
# reason of secret-gone that is not a plain word is not printed.
function Invoke-Status {
  $origin, $token, $null = Read-Link $false
  try {
    $st = Invoke-Api getSecretLink Get "$origin/api/v1/secret-links/$token"
  } catch [ApiError] {
    $e = $_.Exception
    if ($e.Status -eq 410 -and $e.Code -ceq 'secret-gone') { return $(if ($e.Reason -cmatch $ReasonWord) { $e.Reason } else { 'gone' }) }
    # Readable again if the service reopens before the expiry.
    if ($e.Status -eq 403 -and $e.Code -ceq 'express-secrets-disabled') { return 'closed' }
    throw
  }
  "pending $(Format-Date (Get-Prop $st 'expiresAt' $null))"
}

# Writes one line on the standard error, its unprintable characters replaced with U+FFFD: an
# error can quote a problem of the server (code, detail, reason, delay).
function Write-ErrorLine([string]$message) {
  [Console]::Error.WriteLine('express-secret: ' + ($message -replace $Unprintable, [string][char]0xFFFD))
}

function Invoke-Read {
  $origin, $token, $fragment = Read-Link $true
  $key = ConvertFrom-FragmentKey $fragment
  $uri = "$origin/api/v1/secret-links/$token"
  # The status call consumes nothing (404 unknown, 410 secret-gone with a reason, 403 closed).
  $st = Invoke-Api getSecretLink Get $uri
  if ($null -ne (Get-Prop $st 'passphrase' $null)) {
    throw 'this secret has a passphrase: it is not an express secret (use secret-create.ps1 read)'
  }
  if ($null -ne (Get-Prop $st 'file' $null)) {
    throw 'this secret has a file, which this example cannot decrypt: open the link in a browser'
  }
  if (Get-Prop $st 'express' $false) {
    $how = if (Get-Prop $st 'anonymous' $false) { 'anonymously' } else { 'with an API token of the entity' }
    Write-ErrorLine ("this express secret was created ${how}: its content was written by a third party, " +
      'not by the entity, which has not checked it. To report an abuse, use the link on the read page ' +
      'or POST /api/v1/secret-links/<token>/abuse-reports.')
  }
  $rootKey = Get-RootKey $key
  # One-time: the answer is the only copy.
  $revealed = Invoke-Api revealSecret Post "$uri/reveal" @{} ([ordered]@{
      keyProof = ConvertTo-Hex (Get-KeyProof $key); proof = ConvertTo-Hex (Get-Proof $rootKey)
    })
  $text = Unprotect-SecretText $rootKey $revealed.encryptedText
  if ($PassThru) { return $text }   # the exact text, as a string for the caller
  if (-not [Console]::IsOutputRedirected) {
    if ($text -match $TerminalUnsafe) {
      Write-ErrorLine 'control or bidirectional characters replaced with U+FFFD on the terminal: redirect the output to keep the text as is'
      $text = $text -replace $TerminalUnsafe, [string][char]0xFFFD
    }
    [Console]::Out.Write($text)
    return
  }
  # Redirected: the exact UTF-8 bytes, whatever the console encoding.
  $bytes = $Utf8.GetBytes($text)
  $stdout = [Console]::OpenStandardOutput()
  try { $stdout.Write($bytes, 0, $bytes.Length); $stdout.Flush() } finally { $stdout.Dispose() }
}

# --- Self-test against internal/tte2/testdata/vectors.json -----------------------------------

# Checks every secret vector of the express profile (no passphrase, no descriptor); the vectors
# with a passphrase are counted as skipped.
function Invoke-SelfTest {
  if (-not $Vectors) { throw 'self-test needs -Vectors' }
  $v = [IO.File]::ReadAllText($Vectors, $Utf8) | ConvertFrom-Json -NoEnumerate
  $script:failures = 0
  function Assert-Equal([string]$name, $got, $want) {
    if ($got -cne $want) { $script:failures++; [Console]::Error.WriteLine("FAIL ${name}: got $got, want $want") }
  }
  $byName = @{}
  $done = 0; $skipped = 0
  foreach ($s in $v.secrets) {
    $byName[$s.name] = $s
    if ($s.PSObject.Properties['passphrase'] -or $null -ne (Get-Prop $s 'descriptor' $null)) { $skipped++; continue }
    $done++
    $key = ConvertFrom-FragmentKey $s.keyFragment
    Assert-Equal "$($s.name) keyFragment" (ConvertTo-Hex $key) $s.keyHex
    Assert-Equal "$($s.name) encoded key" (ConvertTo-Base64Url ([Convert]::FromHexString($s.keyHex))) $s.keyFragment
    $rootKey = Get-RootKey $key
    Assert-Equal "$($s.name) rootKey" (ConvertTo-Hex $rootKey) $s.rootKeyHex
    $kp = Get-KeyProof $key
    Assert-Equal "$($s.name) keyProof" (ConvertTo-Hex $kp) $s.keyProofHex
    Assert-Equal "$($s.name) keyVerifier" (ConvertTo-Hex (Get-Verifier $kp)) $s.keyVerifierHex
    $pr = Get-Proof $rootKey
    Assert-Equal "$($s.name) proof" (ConvertTo-Hex $pr) $s.proofHex
    Assert-Equal "$($s.name) verifier" (ConvertTo-Hex (Get-Verifier $pr)) $s.verifierHex
    Assert-Equal "$($s.name) sealedText" (Protect-SecretText $rootKey $s.text ([Convert]::FromHexString($s.textNonceHex))) $s.sealedText
    Assert-Equal "$($s.name) open" (Unprotect-SecretText $rootKey $s.sealedText) $s.text
  }
  $negDone = 0; $negSkipped = 0
  foreach ($n in $v.secretNegative) {
    $base = $byName[$n.secret]
    $passphrase = Get-Prop $n 'passphrase' (Get-Prop $base 'passphrase' '')
    $descriptor = if (Get-Prop $n 'noDescriptor' $false) { $null } else { Get-Prop $n 'descriptor' (Get-Prop $base 'descriptor' $null) }
    if ($passphrase -ne '' -or $null -ne $descriptor) { $negSkipped++; continue }
    $negDone++
    $key = [Convert]::FromHexString((Get-Prop $n 'keyHex' $base.keyHex))
    Assert-Equal "$($n.name) keyProofValid" ((ConvertTo-Hex (Get-Verifier (Get-KeyProof $key))) -ceq $base.keyVerifierHex) $n.keyProofValid
    $got = 'none'
    $proofValid = $false
    try {
      $rootKey = Get-RootKey $key
      $proofValid = (ConvertTo-Hex (Get-Verifier (Get-Proof $rootKey))) -ceq $base.verifierHex
      if ($n.PSObject.Properties['text']) { $null = Protect-SecretText $rootKey $n.text }
      else { $null = Unprotect-SecretText $rootKey (Get-Prop $n 'sealed' $base.sealedText) }
    } catch [FormatError] {
      $got = $_.Exception.Code
    }
    Assert-Equal "$($n.name) error" $got $n.expectedError
    Assert-Equal "$($n.name) proofValid" $proofValid $n.proofValid
  }
  if ($done -eq 0 -or $negDone -eq 0) { $script:failures++; [Console]::Error.WriteLine('FAIL no vector of the express profile') }
  if ($script:failures -gt 0) {
    [Console]::Error.WriteLine("self-test: $($script:failures) failure(s)")
    exit 1
  }
  "self-test: ok ($done secrets, $negDone negative cases; skipped with a passphrase: $skipped secrets, $negSkipped negative cases)"
}

# --- Main ------------------------------------------------------------------------------------

# A hint for the problems a script should explain (errors.md has them all).
function Get-Hint([ApiError]$e) {
  $create = $e.Op -ceq 'createExpressSecret'
  $h = switch -CaseSensitive ($e.Code) {
    'express-secrets-disabled' {
      if ($create) { 'express secrets are not open to anonymous use on this entity, or are disabled on the instance: use an API token allowed for them (TT_TOKEN_FILE) or ask the administrators' }
      else { 'the express service of this entity is closed: nothing was consumed, the secret can be read if the service reopens before it expires' }
    }
    'express-token-not-allowed' { 'this API token may not create express secrets: ask an administrator of the entity to allow it (expressAllowed)' }
    'express-secret-limit-reached' { 'the entity holds too many unread express secrets: try later, or use an API token' }
    'invalid-credentials' { 'the API token is unknown, revoked or expired' }
    'ip-not-allowed' { 'this API token is not allowed from this address (allowedCidrs)' }
    'validation-failed' { 'the request was refused as malformed: do not retry it unchanged' }
    'secret-format-invalid' { 'the sealed text was refused: do not retry it unchanged' }
    'secret-proof-invalid' { 'the key of the link is wrong: the link was truncated or altered' }
    'secret-gone' { "the secret is gone ($(if ($e.Reason) { $e.Reason } else { 'unknown reason' }))" }
    'not-found' {
      if ($create) { 'no express secrets on this server (TransTeira 2.3 or later is needed)' }
      else { 'unknown link: mistyped, or made on another entity' }
    }
    default { '' }
  }
  if (($e.Status -eq 429 -or $e.Status -eq 503) -and $e.RetryAfter) {
    $h = "$(if ($h) { "$h; " })retry after $($e.RetryAfter) seconds"
    if ($create) { $h += ' (a new run draws a new key)' }
  }
  $h
}

try {
  switch ($Mode) {
    'create' { Invoke-Create }
    'seal' { Invoke-Seal }
    'status' { Invoke-Status }
    'read' { Invoke-Read }
    'self-test' { Invoke-SelfTest }
  }
} catch {
  $e = $_.Exception
  Write-ErrorLine $e.Message
  if ($e -is [ApiError]) {
    $h = Get-Hint $e
    if ($h) { Write-ErrorLine $h }
  }
  exit 1
}
