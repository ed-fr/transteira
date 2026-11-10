#Requires -Version 7.4
<#
.SYNOPSIS
  Create and read TransTeira one-time secrets from a script (since 2.1).

.DESCRIPTION
  PowerShell 7.4 or later (.NET 8), no module: AesGcm, HKDF, Rfc2898DeriveBytes.Pbkdf2 and
  SHA256 from System.Security.Cryptography, Invoke-RestMethod for the HTTP calls. The format is
  docs/architecture/e2e-format.md section 3.3; the self-test mode checks this file against
  internal/tte2/testdata/vectors.json.

  Modes:
    create -TextFile FILE      create a secret, print its link (or its id for e-mail delivery)
    read                       reveal a secret (once) and print its text
    self-test -Vectors FILE    check the format against the vectors

  The text file is read as UTF-8, as is (no trimming). It must hold 1 to 10 000 Unicode code
  points. This example handles text only: for the optional file, implement the TTE2 stream of
  e2e-format.md section 2 with the root key K' and index 0. The link to read comes from the
  file named by TT_LINK_FILE or, without it, from redirected standard input, never from the
  command line (other users of the host can read the process list).

  Environment:
    TT_URL              tenant URL, e.g. https://transfer.entity-a.example.com (create)
    TT_TOKEN_FILE       file holding the API token (create)
    TT_SENDER           creator address: internal domain, allowed by the token (create)
    TT_EXPIRES          duration offered by the tenant: 1h, 12h, 1d, 3d, 7d or 30d (default 1d)
    TT_RECIPIENT        e-mail delivery to this address; without it the link is printed
    TT_READ_RECEIPT     1 to receive a mail when the secret is read, expires or is locked
    TT_PASSPHRASE_FILE  file holding the passphrase (optional; one trailing line break is
                        dropped, nothing else is trimmed). Send it by another channel.
    TT_SKIP_FILE        read: 1 to reveal a secret that has a file, losing the file (this
                        example cannot decrypt it, and the reveal is one-time)
    TT_LINK_FILE        read: file holding the link (default: redirected standard input)

  The link https://<fqdn>/s/<token>#k=<key> is the secret: write it to a private place only.
  A new key is drawn for every secret, never reused, not even to retry a failed creation.

.EXAMPLE
  $env:TT_URL = 'https://transfer.entity-a.example.com'
  $env:TT_TOKEN_FILE = "$HOME/.config/transteira/token"
  $env:TT_SENDER = 'reporting@entity-a.example.com'
  ./secret-create.ps1 create -TextFile ./db-password.txt > ./secret-link.txt

.EXAMPLE
  $env:TT_LINK_FILE = './secret-link.txt'
  ./secret-create.ps1 read
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory, Position = 0)]
  [ValidateSet('create', 'read', 'self-test')]
  [string]$Mode,
  [string]$TextFile,
  [string]$Vectors
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$KeySize = 32
$NonceSize = 12
$TagSize = 16
$SealedOverhead = 1 + $NonceSize + $TagSize                         # 29 bytes
$MaxSecretRunes = 10000
$MaxSecretEncodedSize = ($SealedOverhead + 4 * $MaxSecretRunes) / 3 * 4  # 53 372
$PassphraseKdf = 'pbkdf2-sha256'
$PassphraseIterations = 600000
$PassphraseSaltSize = 16
$MaxPassphraseSize = 1024
$InfoSecret = 'transteira/tte2/v1/secret'
$InfoKeyProof = 'transteira/tte2/v1/secret/key-proof'
$InfoText = 'transteira/tte2/v1/secret/text'
$InfoProof = 'transteira/tte2/v1/secret/proof'
$SecretAad = [Text.Encoding]::ASCII.GetBytes('TTE2S')
# Strict UTF-8: invalid bytes and lone surrogates throw instead of being replaced.
$Utf8 = [Text.UTF8Encoding]::new($false, $true)
$Sha256 = [Security.Cryptography.HashAlgorithmName]::SHA256

# A format error, named after the Go error of internal/tte2 (e.g. ErrAuth).
class FormatError : Exception {
  [string]$Code
  FormatError([string]$code, [string]$detail) : base("${code}: $detail") { $this.Code = $code }
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

# Number of Unicode code points of a well-formed string.
function Get-RuneCount([string]$s) {
  $n = 0
  foreach ($c in $s.ToCharArray()) { if (-not [char]::IsLowSurrogate($c)) { $n++ } }
  $n
}

# --- Derivations (sections 3.3.2 and 3.3.4) --------------------------------------------------

function Get-Hkdf([byte[]]$ikm, [byte[]]$salt, [string]$info) {
  , [Security.Cryptography.HKDF]::DeriveKey($Sha256, $ikm, $KeySize, $salt, $Utf8.GetBytes($info))
}

function New-Descriptor {
  [pscustomobject]@{
    kdf = $PassphraseKdf; iterations = $PassphraseIterations
    salt = ConvertTo-Base64Url (Get-RandomBytes $PassphraseSaltSize)
  }
}

# K' = HKDF(K, salt = P or empty, InfoSecret), P = PBKDF2-HMAC-SHA-256(NFC passphrase, salt,
# 600000, 32). No passphrase is an empty passphrase with a $null descriptor. The descriptor must
# be exactly the one of the format, when creating and when opening.
function Get-RootKey([byte[]]$key, [string]$passphrase, $descriptor) {
  if ($key.Length -ne $KeySize) { throw [FormatError]::new('ErrInvalidKey', "$($key.Length) bytes") }
  [byte[]]$p = @()
  if ($null -eq $descriptor) {
    if ($passphrase -ne '') { throw [FormatError]::new('ErrInvalidPassphrase', 'passphrase without descriptor') }
  } else {
    $salt = if ($descriptor.salt -is [string] -and $descriptor.salt.Length -eq 22) { ConvertFrom-Base64Url $descriptor.salt } else { $null }
    if ($null -eq $salt -or $descriptor.kdf -cne $PassphraseKdf -or
        $descriptor.iterations -isnot [ValueType] -or $descriptor.iterations -ne $PassphraseIterations -or
        $salt.Length -ne $PassphraseSaltSize) {
      throw [FormatError]::new('ErrInvalidPassphrase', 'unsupported descriptor')
    }
    if ($passphrase -eq '') { throw [FormatError]::new('ErrInvalidPassphrase', 'empty passphrase') }
    try { $bytes = $Utf8.GetBytes($passphrase.Normalize([Text.NormalizationForm]::FormC)) }
    catch { throw [FormatError]::new('ErrInvalidPassphrase', 'lone surrogate') }
    if ($bytes.Length -gt $MaxPassphraseSize) {
      throw [FormatError]::new('ErrInvalidPassphrase', "longer than $MaxPassphraseSize bytes")
    }
    $p = [Security.Cryptography.Rfc2898DeriveBytes]::Pbkdf2($bytes, $salt, $PassphraseIterations, $Sha256, $KeySize)
  }
  , (Get-Hkdf $key $p $InfoSecret)
}

function Get-KeyProof([byte[]]$key) { , (Get-Hkdf $key @() $InfoKeyProof) }
function Get-Proof([byte[]]$rootKey) { , (Get-Hkdf $rootKey @() $InfoProof) }
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
  $aes = [Security.Cryptography.AesGcm]::new((Get-Hkdf $rootKey @() $InfoText), $TagSize)
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
  $aes = [Security.Cryptography.AesGcm]::new((Get-Hkdf $rootKey @() $InfoText), $TagSize)
  try { $aes.Decrypt($nonce, $ct, $tag, $plain, $SecretAad) }
  catch [Security.Cryptography.AuthenticationTagMismatchException] {
    throw [FormatError]::new('ErrAuth', 'wrong key or passphrase, or altered')
  } finally { $aes.Dispose() }
  try { $text = $Utf8.GetString($plain) } catch { throw [FormatError]::new('ErrInvalidSecret', 'not valid UTF-8') }
  Test-TextLength $text
  $text
}

# --- HTTP ------------------------------------------------------------------------------------

function Get-Env([string]$name, [string]$default) {
  $v = [Environment]::GetEnvironmentVariable($name)
  if ($v) { return $v }
  if ($PSBoundParameters.ContainsKey('default')) { return $default }
  throw "$name is required"
}

# Reads the passphrase file, dropping one trailing line break only.
function Read-Passphrase {
  if (-not $env:TT_PASSPHRASE_FILE) { return '' }
  [IO.File]::ReadAllText($env:TT_PASSPHRASE_FILE, $Utf8) -replace '\r?\n\z', ''
}

# Calls the API operation $op; a non-2xx answer throws with the problem code (RFC 9457). The
# error names the operation, not the path, which may hold a secret token. Redirects are refused.
function Invoke-Api([string]$op, [string]$method, [string]$uri, [hashtable]$headers = @{}, $body) {
  $params = @{
    Method = $method; Uri = $uri; Headers = $headers; SkipHttpErrorCheck = $true
    StatusCodeVariable = 'status'; MaximumRedirection = 0
  }
  if ($null -ne $body) {
    $params.ContentType = 'application/json'
    $params.Body = $Utf8.GetBytes(($body | ConvertTo-Json -Depth 5 -Compress))
  }
  $res = Invoke-RestMethod @params
  if ($status -lt 200 -or $status -ge 300) {
    throw "${op}: $status $($res.code) $($res.detail)"
  }
  $res
}

function Invoke-Create {
  if (-not $TextFile) { throw 'create needs -TextFile' }
  $base = (Get-Env 'TT_URL').TrimEnd('/')
  if (-not $base.StartsWith('https://')) { throw 'TT_URL must start with https://' }
  $auth = @{ Authorization = "Bearer $((Get-Content -Raw (Get-Env 'TT_TOKEN_FILE')).Trim())" }
  $text = [IO.File]::ReadAllText($TextFile, $Utf8)
  if ($text -eq '') { throw 'empty text (allowed only with a file, not handled here)' }
  $passphrase = Read-Passphrase

  # A new key for every secret. Open the sealed text before sending, so that the verifiers
  # never certify a text the recipient could not open.
  $key = Get-RandomBytes $KeySize
  $descriptor = if ($passphrase -ne '') { New-Descriptor } else { $null }
  $rootKey = Get-RootKey $key $passphrase $descriptor
  $sealed = Protect-SecretText $rootKey $text
  if ((Unprotect-SecretText $rootKey $sealed) -cne $text) { throw 'self-check failed' }

  $recipient = $env:TT_RECIPIENT
  $body = [ordered]@{
    encryptedText = $sealed
    keyVerifier   = ConvertTo-Hex (Get-Verifier (Get-KeyProof $key))
    verifier      = ConvertTo-Hex (Get-Verifier (Get-Proof $rootKey))
    expiresIn     = Get-Env 'TT_EXPIRES' '1d'
    delivery      = if ($recipient) { 'email' } else { 'link' }
    senderEmail   = Get-Env 'TT_SENDER'
    readReceipt   = $env:TT_READ_RECEIPT -eq '1'
  }
  if ($descriptor) { $body.passphrase = $descriptor }
  if ($recipient) { $body.recipient = $recipient }
  $created = Invoke-Api createSecret Post "$base/api/v1/secrets" $auth $body
  $fragmentKey = ConvertTo-Base64Url $key
  if (-not $recipient) {
    # Link delivery: the secret is active at once. The link is shown here only.
    "$base/s/$($created.token)#k=$fragmentKey"
    return
  }
  # E-mail delivery: the server composes the link with both halves, sent once. On
  # 503 mail-unavailable the secret stays pending (purged after 1 hour): retry send.
  $sent = Invoke-Api sendSecret Post "$base/api/v1/secrets/$($created.id)/send" $auth @{
    secretToken = $created.token; fragmentKey = $fragmentKey
  }
  "$($sent.id) $($sent.state) expires $($sent.expiresAt)"
}

# Reads the link from TT_LINK_FILE or redirected standard input, dropping surrounding white space.
function Read-Link {
  if ($env:TT_LINK_FILE) { return [IO.File]::ReadAllText($env:TT_LINK_FILE, $Utf8).Trim() }
  if (-not [Console]::IsInputRedirected) { return '' }
  [Console]::In.ReadToEnd().Trim()
}

function Invoke-Read {
  if ((Read-Link) -cnotmatch '^(https://[^/?#]+)/s/(tts_[A-Za-z0-9]{43})#k=([A-Za-z0-9_-]{43})$') {
    throw 'read needs https://<fqdn>/s/<token>#k=<key> in TT_LINK_FILE or on standard input'
  }
  $origin, $secretToken, $fragment = $Matches[1], $Matches[2], $Matches[3]
  $key = ConvertFrom-FragmentKey $fragment
  $uri = "$origin/api/v1/secret-links/$secretToken"
  # The status call consumes nothing (404 unknown, 410 secret-gone with a reason).
  $status = Invoke-Api getSecretLink Get $uri
  if ($null -ne $status.file -and $env:TT_SKIP_FILE -ne '1') {
    throw 'this secret has a file that this example cannot decrypt; set TT_SKIP_FILE=1 to reveal the text and lose the file'
  }
  $descriptor = if ($status.PSObject.Properties['passphrase']) { $status.passphrase } else { $null }
  $passphrase = if ($descriptor) { Read-Passphrase } else { '' }
  if ($descriptor -and $passphrase -eq '') { throw 'this secret needs a passphrase: set TT_PASSPHRASE_FILE' }
  $rootKey = Get-RootKey $key $passphrase $descriptor
  # One-time: the answer is the only copy (a wrong passphrase gets 403 secret-proof-invalid with
  # attemptsRemaining; the fifth counted failure locks the secret).
  $revealed = Invoke-Api revealSecret Post "$uri/reveal" @{} @{
    keyProof = ConvertTo-Hex (Get-KeyProof $key); proof = ConvertTo-Hex (Get-Proof $rootKey)
  }
  [Console]::Out.Write((Unprotect-SecretText $rootKey $revealed.encryptedText))
}

# --- Self-test against internal/tte2/testdata/vectors.json -----------------------------------

function Invoke-SelfTest {
  if (-not $Vectors) { throw 'self-test needs -Vectors' }
  $v = [IO.File]::ReadAllText($Vectors, $Utf8) | ConvertFrom-Json -NoEnumerate
  $script:failures = 0
  function Assert-Equal([string]$name, $got, $want) {
    if ($got -cne $want) { $script:failures++; [Console]::Error.WriteLine("FAIL ${name}: got $got, want $want") }
  }
  function Get-Prop($o, [string]$name, $default) {
    if ($o.PSObject.Properties[$name]) { $o.$name } else { $default }
  }
  $byName = @{}
  foreach ($s in $v.secrets) {
    $byName[$s.name] = $s
    $key = ConvertFrom-FragmentKey $s.keyFragment
    Assert-Equal "$($s.name) keyFragment" (ConvertTo-Hex $key) $s.keyHex
    Assert-Equal "$($s.name) encoded key" (ConvertTo-Base64Url ([Convert]::FromHexString($s.keyHex))) $s.keyFragment
    $passphrase = Get-Prop $s 'passphrase' ''
    if ($s.PSObject.Properties['passphraseNfcHex']) {
      Assert-Equal "$($s.name) NFC" (ConvertTo-Hex $Utf8.GetBytes($passphrase.Normalize([Text.NormalizationForm]::FormC))) $s.passphraseNfcHex
    }
    $rootKey = Get-RootKey $key $passphrase (Get-Prop $s 'descriptor' $null)
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
  foreach ($n in $v.secretNegative) {
    $base = $byName[$n.secret]
    $key = [Convert]::FromHexString((Get-Prop $n 'keyHex' $base.keyHex))
    $passphrase = Get-Prop $n 'passphrase' (Get-Prop $base 'passphrase' '')
    $descriptor = if (Get-Prop $n 'noDescriptor' $false) { $null } else { Get-Prop $n 'descriptor' (Get-Prop $base 'descriptor' $null) }
    Assert-Equal "$($n.name) keyProofValid" ((ConvertTo-Hex (Get-Verifier (Get-KeyProof $key))) -ceq $base.keyVerifierHex) $n.keyProofValid
    $got = 'none'
    $proofValid = $false
    try {
      $rootKey = Get-RootKey $key $passphrase $descriptor
      $proofValid = (ConvertTo-Hex (Get-Verifier (Get-Proof $rootKey))) -ceq $base.verifierHex
      if ($n.PSObject.Properties['text']) { $null = Protect-SecretText $rootKey $n.text }
      else { $null = Unprotect-SecretText $rootKey (Get-Prop $n 'sealed' $base.sealedText) }
    } catch [FormatError] {
      $got = $_.Exception.Code
    }
    Assert-Equal "$($n.name) error" $got $n.expectedError
    Assert-Equal "$($n.name) proofValid" $proofValid $n.proofValid
  }
  if ($script:failures -gt 0) {
    [Console]::Error.WriteLine("self-test: $($script:failures) failure(s)")
    exit 1
  }
  "self-test: ok ($($v.secrets.Count) secrets, $($v.secretNegative.Count) negative cases)"
}

try {
  switch ($Mode) {
    'create' { Invoke-Create }
    'read' { Invoke-Read }
    'self-test' { Invoke-SelfTest }
  }
} catch {
  [Console]::Error.WriteLine("secret-create: $($_.Exception.Message)")
  exit 1
}
