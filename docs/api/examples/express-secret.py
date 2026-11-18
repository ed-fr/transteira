#!/usr/bin/env python3
"""express-secret.py: create and read TransTeira express secrets from a script (since 2.3).

Python 3.11 or later with the "cryptography" package for AES-256-GCM and HKDF-SHA-256, pinned
with its hashes in requirements.txt:

    python3 -m pip install --require-hashes --only-binary=:all: -r requirements.txt

Everything else is the standard library (secrets for the key, hashlib, urllib for the HTTP
calls). The format is docs/architecture/e2e-format.md section 3.3.9 (express profile of the
one-time secrets: no passphrase, no file, link composed by the client); the self-test mode checks
this file against internal/tte2/testdata/vectors.json.

Usage:
  python3 express-secret.py create [--file FILE]   create an express secret, print its link
  python3 express-secret.py seal [--file FILE]     print the createExpressSecret body and the key
  python3 express-secret.py status                 print the state of a link (consumes nothing)
  python3 express-secret.py read                   reveal a secret (once) and print its text
  python3 express-secret.py self-test VECTORS.json check the format against the vectors

The text comes from standard input or from --file FILE, never from the command line (other
users of the host can read the process list). It is used as is, as UTF-8, with no trimming (use
printf, not echo, to avoid a trailing line break), and must hold 1 to 10 000 Unicode code
points. The link of status and read comes from the file named by TT_LINK_FILE or, without it,
from standard input.

Environment:
  TT_URL         tenant URL, e.g. https://transfer.entity-a.example.com (create)
  TT_TOKEN_FILE  file holding an API token of the entity allowed to create express secrets
                 (expressAllowed); without it the creation is anonymous (create)
  TT_EXPIRES     1h, 1d or 7d (default 1d) (create, seal)
  TT_LINK_FILE   status, read: file holding the link (default: standard input)
  TT_CA_FILE     extra CA certificates (PEM) to trust, for an internal PKI (optional)

The link https://<fqdn>/s/<token>#k=<key> is the secret: create prints it on standard output
only, never in a log; write it to a private place. A new key is drawn for every secret, never
reused, not even to retry a failed creation. The server never receives the text nor the key.

seal prints {"fragmentKey": "...", "body": {...}}, where body is the complete request body of
POST /api/v1/express-secrets (encryptedText, verifier, keyVerifier, expiresIn): see the
integration guide (docs/api/integration.md) for the curl calls around it.
"""

import argparse
import base64
import hashlib
import json
import functools
import os
import re
import secrets
import ssl
import sys
import urllib.error
import urllib.request

if sys.version_info < (3, 11):
    sys.exit("express-secret: Python 3.11 or later is required")

from cryptography.exceptions import InvalidTag  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: E402

KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16
SEALED_OVERHEAD = 1 + NONCE_SIZE + TAG_SIZE  # 29 bytes: version, nonce, tag
MAX_SECRET_RUNES = 10000
MAX_SECRET_ENCODED_SIZE = (SEALED_OVERHEAD + 4 * MAX_SECRET_RUNES) // 3 * 4  # 53 372
INFO_SECRET = b"transteira/tte2/v1/secret"
INFO_KEY_PROOF = b"transteira/tte2/v1/secret/key-proof"
INFO_TEXT = b"transteira/tte2/v1/secret/text"
INFO_PROOF = b"transteira/tte2/v1/secret/proof"
SECRET_AAD = b"TTE2S"
DURATIONS = ("1h", "1d", "7d")
TIMEOUT = 60  # seconds per HTTP call

BASE64URL = re.compile(r"[A-Za-z0-9_-]*")
ORIGIN = re.compile(r"https://[^/?#@\s]+")
LINK = re.compile(r"(https://[^/?#@\s]+)/s/(tts_[A-Za-z0-9]{43})(?:#k=([A-Za-z0-9_-]{43}))?")
SECRET_TOKEN = re.compile(r"tts_[A-Za-z0-9]{43}")
# Characters that could drive or deceive a terminal: C0 controls, DEL and C1 controls (escape
# sequences), and the bidirectional formatting characters (they could reorder what is shown).
# Replaced in every message (line breaks included), since an error can quote a problem of the
# server named by the link, which may be hostile.
UNPRINTABLE = re.compile(r"[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")
# Replaced before a revealed text is shown on a terminal: the same characters except tab, line
# feed and a carriage return right before a line feed (a lone carriage return would send the
# cursor back to the start of the line and let the rest of the line overwrite what was shown).
TERMINAL_UNSAFE = re.compile(r"\r(?!\n)|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")
# What status prints: an RFC 3339 date, and a reason of secret-gone that is a plain word (read,
# expired, deleted, locked, or one a later server may add).
RFC3339 = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})")
REASON_WORD = re.compile(r"[a-z][a-z0-9_-]{0,31}")


class FormatError(Exception):
    """A format error, named after the Go error of internal/tte2 (e.g. ErrAuth)."""

    def __init__(self, code, detail):
        super().__init__(f"{code}: {detail}")
        self.code = code


class ApiError(Exception):
    """
    A non-2xx answer: the operation, the status and the problem (RFC 9457). Its strings come
    from the server: warn makes them printable.
    """

    def __init__(self, op, status, problem, retry_after):
        code = problem.get("code", "")
        code = code if isinstance(code, str) else ""
        super().__init__(f"{op}: {status} {code} {problem.get('detail', '')}".rstrip())
        self.op, self.status, self.code, self.problem = op, status, code, problem
        self.retry_after = retry_after


# --- Encodings ---------------------------------------------------------------------------------


def b64url(b):
    """base64url without padding."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def from_b64url(s):
    """Strict base64url: alphabet only, no padding, canonical; None otherwise."""
    if not BASE64URL.fullmatch(s) or len(s) % 4 == 1:
        return None
    b = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    return b if b64url(b) == s else None


def decode_key(s):
    """The key of a link fragment: 43 canonical base64url characters, 32 bytes."""
    k = from_b64url(s) if len(s) == 43 else None
    if k is None:
        raise FormatError("ErrInvalidKey", "not 43 canonical base64url characters")
    return k


# --- Derivations (sections 3.3.2, 3.3.4 and 3.3.9) ---------------------------------------------


def hkdf(ikm, info):
    """HKDF-SHA-256 of 32 bytes with an empty salt."""
    return HKDF(algorithm=hashes.SHA256(), length=KEY_SIZE, salt=b"", info=info).derive(ikm)


def root_key(key):
    """K' = HKDF(K, salt = empty, "transteira/tte2/v1/secret"): an express secret has no passphrase."""
    if len(key) != KEY_SIZE:
        raise FormatError("ErrInvalidKey", f"{len(key)} bytes")
    return hkdf(key, INFO_SECRET)


def key_proof(key):
    return hkdf(key, INFO_KEY_PROOF)


def proof(rk):
    return hkdf(rk, INFO_PROOF)


def verifier(p):
    return hashlib.sha256(p).digest()


# --- Text (section 3.3.3) ----------------------------------------------------------------------


def check_text(text):
    # A Python string is a sequence of code points: len() is the count of the format.
    if len(text) > MAX_SECRET_RUNES:
        raise FormatError("ErrInvalidSecret", f"longer than {MAX_SECRET_RUNES} characters")


def seal_text(rk, text, nonce=None):
    """Seals the text: base64url(0x01 || nonce || AES-256-GCM(text, AAD "TTE2S") || tag)."""
    try:
        plain = text.encode("utf-8")  # strict: a lone surrogate raises
    except UnicodeEncodeError:
        raise FormatError("ErrInvalidSecret", "lone surrogate") from None
    check_text(text)
    nonce = secrets.token_bytes(NONCE_SIZE) if nonce is None else nonce
    ct = AESGCM(hkdf(rk, INFO_TEXT)).encrypt(nonce, plain, SECRET_AAD)
    return b64url(b"\x01" + nonce + ct)


def open_text(rk, sealed):
    """Opens a sealed text: strict framing (ErrEncoding), tag (ErrAuth), then the text rules."""
    blob = from_b64url(sealed) if len(sealed) <= MAX_SECRET_ENCODED_SIZE else None
    if blob is None or len(blob) < SEALED_OVERHEAD or blob[0] != 1:
        raise FormatError("ErrEncoding", "not a sealed secret text")
    try:
        plain = AESGCM(hkdf(rk, INFO_TEXT)).decrypt(blob[1 : 1 + NONCE_SIZE], blob[1 + NONCE_SIZE :], SECRET_AAD)
    except InvalidTag:
        raise FormatError("ErrAuth", "wrong key, or altered") from None
    try:
        text = plain.decode("utf-8")  # strict; a leading U+FEFF is kept, as in Go
    except UnicodeDecodeError:
        raise FormatError("ErrInvalidSecret", "not valid UTF-8") from None
    check_text(text)
    return text


# --- Creation ----------------------------------------------------------------------------------


def seal_secret(text, expires_in):
    """
    Seals text under a new key and returns the fragment key and the createExpressSecret body. It
    opens its own sealed text before returning, so that the verifiers never certify a text the
    recipient could not open.
    """
    if text == "":
        raise ValueError("empty text: an express secret holds 1 to 10 000 characters")
    if len(text) > MAX_SECRET_RUNES:
        raise ValueError(f"text of {len(text)} characters: at most {MAX_SECRET_RUNES}")
    if expires_in not in DURATIONS:
        raise ValueError(f"TT_EXPIRES must be 1h, 1d or 7d, not {expires_in!r}")
    key = secrets.token_bytes(KEY_SIZE)  # a new key for every secret, from the CSPRNG
    rk = root_key(key)
    encrypted_text = seal_text(rk, text)
    if open_text(rk, encrypted_text) != text:
        raise RuntimeError("self-check failed")
    body = {
        "encryptedText": encrypted_text,
        "verifier": verifier(proof(rk)).hex(),
        "keyVerifier": verifier(key_proof(key)).hex(),
        "expiresIn": expires_in,
    }
    return b64url(key), body


def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def read_text(path):
    """Reads the text, as is, from the file or standard input; invalid UTF-8 is refused."""
    raw = read_bytes(path) if path else sys.stdin.buffer.read()
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("the text is not valid UTF-8") from None


def tls_context():
    ctx = ssl.create_default_context()
    ca = os.environ.get("TT_CA_FILE", "")
    if ca:
        ctx.load_verify_locations(cafile=ca)  # in addition to the system store
    return ctx


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuses redirects: a 3xx answer is an error, never followed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@functools.cache
def opener():
    return urllib.request.build_opener(urllib.request.HTTPSHandler(context=tls_context()), NoRedirect())


def call(op, method, url, headers=None, body=None):
    """
    Calls the API operation op and returns the decoded JSON answer; a non-2xx answer raises
    ApiError with the problem (RFC 9457). Errors name the operation, never the path, which may
    hold a secret token.
    """
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for name, value in (headers or {}).items():
        req.add_header(name, value)
    try:
        with opener().open(req, timeout=TIMEOUT) as res:
            return json.loads(res.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            problem = json.loads(e.read() or b"{}")
        except ValueError:
            problem = {}
        if not isinstance(problem, dict):
            problem = {}
        raise ApiError(op, e.code, problem, e.headers.get("Retry-After")) from None
    except urllib.error.URLError as e:
        raise ConnectionError(f"{op}: {e.reason}") from None


def create(args):
    base = env("TT_URL").rstrip("/")
    if not ORIGIN.fullmatch(base):
        raise ValueError("TT_URL must be https://<fqdn of the entity>, without a path")
    headers = {}
    token_file = os.environ.get("TT_TOKEN_FILE", "")
    if token_file:
        token = read_bytes(token_file).decode("utf-8").strip()
        if not token:
            raise ValueError("TT_TOKEN_FILE is empty")
        headers["Authorization"] = f"Bearer {token}"
    fragment_key, body = seal_secret(read_text(args.file), env("TT_EXPIRES", "1d"))
    created = call("createExpressSecret", "POST", f"{base}/api/v1/express-secrets", headers, body)
    if not SECRET_TOKEN.fullmatch(str(created.get("token", ""))):
        raise ValueError("createExpressSecret: unexpected answer")
    # The client composes the link; the server never sees the fragment. Standard output only.
    sys.stdout.write(f"{base}/s/{created['token']}#k={fragment_key}\n")


def seal(args):
    fragment_key, body = seal_secret(read_text(args.file), env("TT_EXPIRES", "1d"))
    sys.stdout.write(json.dumps({"fragmentKey": fragment_key, "body": body}) + "\n")


# --- Status and reading ------------------------------------------------------------------------


def read_link(need_key):
    """Reads the link from TT_LINK_FILE or standard input, dropping surrounding white space."""
    path = os.environ.get("TT_LINK_FILE", "")
    raw = read_bytes(path) if path else sys.stdin.buffer.read()
    m = LINK.fullmatch(raw.decode("utf-8", "replace").strip())
    if not m or (need_key and m.group(3) is None):
        form = "https://<fqdn>/s/<token>#k=<key>" if need_key else "https://<fqdn>/s/<token>[#k=<key>]"
        raise ValueError(f"expected {form} in TT_LINK_FILE or on standard input")
    return m.group(1), m.group(2), m.group(3)


def status(_args):
    """Prints pending <expiresAt>, read, expired, deleted, locked or closed. Consumes nothing."""
    origin, token, _ = read_link(need_key=False)
    try:
        st = call("getSecretLink", "GET", f"{origin}/api/v1/secret-links/{token}")
    except ApiError as e:
        if e.status == 410 and e.code == "secret-gone":
            reason = e.problem.get("reason")
            ok = isinstance(reason, str) and REASON_WORD.fullmatch(reason)
            sys.stdout.write(f"{reason if ok else 'gone'}\n")
            return
        if e.status == 403 and e.code == "express-secrets-disabled":
            sys.stdout.write("closed\n")  # readable again if the service reopens before expiry
            return
        raise
    expires_at = st.get("expiresAt") if isinstance(st, dict) else None
    if not isinstance(expires_at, str) or not RFC3339.fullmatch(expires_at):
        raise ValueError("getSecretLink: unexpected answer")
    sys.stdout.write(f"pending {expires_at}\n")


def printable(message):
    """The message for one line: every character of UNPRINTABLE replaced with U+FFFD."""
    return UNPRINTABLE.sub("\ufffd", str(message))


def warn(message):
    sys.stderr.write(f"express-secret: {printable(message)}\n")


def read(_args):
    origin, token, fragment = read_link(need_key=True)
    key = decode_key(fragment)
    url = f"{origin}/api/v1/secret-links/{token}"
    # The status call consumes nothing (404 unknown, 410 secret-gone with a reason, 403 closed).
    st = call("getSecretLink", "GET", url)
    if "passphrase" in st:
        raise ValueError("this secret has a passphrase: it is not an express secret (use secret-create.mjs read)")
    if st.get("file") is not None:
        raise ValueError("this secret has a file, which this example cannot decrypt: open the link in a browser")
    if st.get("express"):
        how = "anonymously" if st.get("anonymous") else "with an API token of the entity"
        warn(
            f"this express secret was created {how}: its content was written by a third party, "
            "not by the entity, which has not checked it. To report an abuse, use the link on "
            "the read page or POST /api/v1/secret-links/<token>/abuse-reports."
        )
    rk = root_key(key)
    # One-time: the answer is the only copy.
    revealed = call("revealSecret", "POST", f"{url}/reveal", {}, {"keyProof": key_proof(key).hex(), "proof": proof(rk).hex()})
    text = open_text(rk, revealed["encryptedText"])
    if sys.stdout.isatty() and TERMINAL_UNSAFE.search(text):
        warn("control or bidirectional characters replaced with U+FFFD on the terminal: redirect the output to keep the text as is")
        text = TERMINAL_UNSAFE.sub("�", text)
    sys.stdout.buffer.write(text.encode("utf-8"))
    sys.stdout.buffer.flush()


# --- Self-test against internal/tte2/testdata/vectors.json -------------------------------------


def self_test(args):
    """
    Checks every secret vector of the express profile (no passphrase, no descriptor); the
    vectors with a passphrase are counted as skipped.
    """
    with open(args.vectors, encoding="utf-8") as f:
        vectors = json.load(f)
    failures = 0

    def check(name, got, want):
        nonlocal failures
        if got != want:
            failures += 1
            sys.stderr.write(f"FAIL {name}: got {got!r}, want {want!r}\n")

    by_name = {}
    done = skipped = 0
    for v in vectors["secrets"]:
        by_name[v["name"]] = v
        if "passphrase" in v or v.get("descriptor") is not None:
            skipped += 1
            continue
        done += 1
        n = v["name"]
        key = decode_key(v["keyFragment"])
        check(f"{n} keyFragment", key.hex(), v["keyHex"])
        check(f"{n} encoded key", b64url(bytes.fromhex(v["keyHex"])), v["keyFragment"])
        rk = root_key(key)
        check(f"{n} rootKey", rk.hex(), v["rootKeyHex"])
        kp = key_proof(key)
        check(f"{n} keyProof", kp.hex(), v["keyProofHex"])
        check(f"{n} keyVerifier", verifier(kp).hex(), v["keyVerifierHex"])
        pr = proof(rk)
        check(f"{n} proof", pr.hex(), v["proofHex"])
        check(f"{n} verifier", verifier(pr).hex(), v["verifierHex"])
        check(f"{n} sealedText", seal_text(rk, v["text"], bytes.fromhex(v["textNonceHex"])), v["sealedText"])
        check(f"{n} open", open_text(rk, v["sealedText"]), v["text"])
    neg_done = neg_skipped = 0
    for c in vectors["secretNegative"]:
        base = by_name[c["secret"]]
        passphrase = c["passphrase"] if "passphrase" in c else base.get("passphrase", "")
        descriptor = None if c.get("noDescriptor") else c.get("descriptor", base.get("descriptor"))
        if passphrase != "" or descriptor is not None:
            neg_skipped += 1
            continue
        neg_done += 1
        n = c["name"]
        key = bytes.fromhex(c.get("keyHex", base["keyHex"]))
        check(f"{n} keyProofValid", verifier(key_proof(key)).hex() == base["keyVerifierHex"], c["keyProofValid"])
        got, proof_valid = "none", False
        try:
            rk = root_key(key)
            proof_valid = verifier(proof(rk)).hex() == base["verifierHex"]
            if "text" in c:
                seal_text(rk, c["text"])
            else:
                open_text(rk, c.get("sealed", base["sealedText"]))
        except FormatError as e:
            got = e.code
        check(f"{n} error", got, c["expectedError"])
        check(f"{n} proofValid", proof_valid, c["proofValid"])
    if done == 0 or neg_done == 0:
        failures += 1
        sys.stderr.write("FAIL no vector of the express profile\n")
    if failures:
        sys.stderr.write(f"self-test: {failures} failure(s)\n")
        sys.exit(1)
    print(
        f"self-test: ok ({done} secrets, {neg_done} negative cases; "
        f"skipped with a passphrase: {skipped} secrets, {neg_skipped} negative cases)"
    )


# --- Main --------------------------------------------------------------------------------------


def env(name, default=None):
    v = os.environ.get(name, "")
    if v:
        return v
    if default is not None:
        return default
    raise ValueError(f"{name} is required")


def hint(e):
    """A hint for the problems a script should explain (errors.md has them all)."""
    create = e.op == "createExpressSecret"
    h = {
        "express-secrets-disabled": (
            "express secrets are not open to anonymous use on this entity, or are disabled on the "
            "instance: use an API token allowed for them (TT_TOKEN_FILE) or ask the administrators"
            if create
            else "the express service of this entity is closed: nothing was consumed, the secret "
            "can be read if the service reopens before it expires"
        ),
        "express-token-not-allowed": "this API token may not create express secrets: ask an "
        "administrator of the entity to allow it (expressAllowed)",
        "express-secret-limit-reached": "the entity holds too many unread express secrets: try "
        "later, or use an API token",
        "invalid-credentials": "the API token is unknown, revoked or expired",
        "ip-not-allowed": "this API token is not allowed from this address (allowedCidrs)",
        "validation-failed": "the request was refused as malformed: do not retry it unchanged",
        "secret-format-invalid": "the sealed text was refused: do not retry it unchanged",
        "secret-proof-invalid": "the key of the link is wrong: the link was truncated or altered",
        "secret-gone": f"the secret is gone ({e.problem.get('reason', 'unknown reason')})",
        "not-found": "no express secrets on this server (TransTeira 2.3 or later is needed)"
        if create
        else "unknown link: mistyped, or made on another entity",
    }.get(e.code, "")
    wait = e.retry_after or e.problem.get("retryAfterSeconds")
    if e.status in (429, 503) and wait:
        h = f"{h + '; ' if h else ''}retry after {wait} seconds"
        if create:
            h += " (a new run draws a new key)"
    return h


def main():
    parser = argparse.ArgumentParser(prog="express-secret.py", description="TransTeira express secrets (since 2.3).")
    sub = parser.add_subparsers(dest="mode", required=True)
    for name, fn in (("create", create), ("seal", seal)):
        p = sub.add_parser(name)
        p.add_argument("--file", help="read the text from FILE instead of standard input")
        p.set_defaults(fn=fn)
    sub.add_parser("status").set_defaults(fn=status)
    sub.add_parser("read").set_defaults(fn=read)
    p = sub.add_parser("self-test")
    p.add_argument("vectors", metavar="VECTORS.json")
    p.set_defaults(fn=self_test)
    args = parser.parse_args()
    try:
        args.fn(args)
    except ApiError as e:
        warn(str(e))
        h = hint(e)
        if h:
            warn(h)
        sys.exit(1)
    except (FormatError, ValueError, OSError, RuntimeError, KeyError) as e:
        warn(str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
