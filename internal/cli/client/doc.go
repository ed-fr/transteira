// Package client is the HTTP layer of the TransTeira command-line client
// (cmd/transteira-cli): configuration, HTTPS transport, authentication,
// retries and RFC 9457 problem decoding. The upload and download packages
// build on it; they never create their own http.Client.
//
// # Configuration
//
// [Load] resolves a [Config] from, in order of precedence, the command-line
// flags ([LoadOptions]), the environment (TT_URL, TT_TOKEN, TT_TOKEN_FILE,
// TT_SENDER, TT_PROFILE, TT_CLI_CONFIG, TT_CA_FILE) and a profile of the
// configuration file (os.UserConfigDir()/transteira/config.json by
// default):
//
//	{"default":"a","profiles":{"a":{"url":"https://transfer.entity-a.example.com",
//	  "tokenFile":"/home/user/.config/transteira/a.token","sender":"user@entity-a.example.com"}}}
//
// The token is never taken from a flag (threat T-328): only from TT_TOKEN,
// a token file (--token-file, TT_TOKEN_FILE, tokenFile) or the profile.
// Outside Windows, the configuration file and the token file are refused
// when the group or others have any right on them, as SSH does. A Config
// never prints its token: String, GoString, LogValue and MarshalJSON redact
// it.
//
// # Transport
//
// [New] returns a [Client] whose transport speaks HTTPS only, TLS 1.2 at
// least, trusts the system roots plus the optional CA file, honors
// HTTPS_PROXY, and never follows a redirect (threat T-329). There is no way
// to disable certificate verification. Requests only ever go to the
// configured origin: a reference to another host is refused before any
// connection, so the Authorization header and the download cookies (kept
// in an in-memory jar) never leave that origin.
//
// # Requests and retries
//
// [Client.Do] sends a request under a [Policy]: it adds the bearer token
// (unless [Policy.Anonymous]), retries connection errors, 408, 429 and 5xx
// answers (except 501 and 507) with a growing pause or the Retry-After
// delay, and turns every other non-2xx answer into a [*Problem]. Callers
// that need their own resume logic (tus PATCH) use MaxAttempts 1 with
// [IsRetryable] and [Client.Pause]. [Client.JSON] wraps Do for JSON
// calls with bounded encoding and decoding.
//
// # Verbose log
//
// With [WithLogger], every attempt writes one line: method, path, status,
// X-Request-Id and duration. The path goes through [Redact] (no query, no
// fragment, bearer-like identifiers such as dl_ links and upl_ uploads cut
// to a short prefix); headers, cookies and the token are never written.
package client
