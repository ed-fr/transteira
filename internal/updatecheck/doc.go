// Package updatecheck checks for a newer release of TransTeira (CLAUDE.md
// V1.2, "version display and update check"; threat model T-244 to T-248,
// trust boundary TB12, decision P52). It never updates anything: it only
// tells the super admin that a newer release exists.
//
// # What is sent
//
// One anonymous request, GET [ReleasesURL], fixed in the code and not
// configurable. The only header of its own is "User-Agent:
// TransTeira/<version>"; no cookie, no GitHub token, no identifier of the
// instance, of a tenant or of a FQDN. The Go transport adds its usual
// Accept-Encoding and decompresses the answer itself.
//
// # What is kept
//
// The answer is read on at most [MaxBody] bytes (a longer one is refused)
// as strict JSON, of which only tag_name, html_url, draft and prerelease
// are read: the name and the notes of the release are never decoded,
// stored nor relayed. The version is kept only when it is a strict SemVer
// of at most [MaxVersionLength] characters (an optional leading "v"
// removed); a draft, a pre-release (flag or SemVer suffix) is ignored. The
// release URL is kept only when it is a page under [ReleasePagePrefix]
// (see [FilterReleaseURL]), otherwise it is null and the version is still
// shown. A newer release is announced only when its version is strictly
// greater than the running one ([Compare]).
//
// # Transport: proxy, TLS, no egress guard
//
// The client verifies TLS against the system roots (or SSL_CERT_FILE),
// with no option to disable it, follows no redirect, gives up after
// [Timeout] and keeps no connection open between checks. It honors
// HTTPS_PROXY / NO_PROXY (http.ProxyFromEnvironment): the instances behind
// a corporate proxy can reach GitHub. That proxy applies to this client
// only; the webhooks and the antivirus engines never use it.
//
// Unlike the webhook client, this client does not dial through the egress
// guard of internal/netpolicy (T-181), on purpose. The guard exists
// because the webhook destinations are chosen by an admin and could aim at
// the internal network (SSRF); here the destination is a constant of the
// code, so no input can redirect the request. Behind a proxy, the guard
// would also check the wrong address, the proxy's, which is usually on a
// private network the guard refuses, and would make the feature unusable
// exactly where a proxy is needed. The protection that matters is end to
// end: TLS is verified against api.github.com through the CONNECT tunnel,
// so neither the proxy nor the network can alter the answer without a
// certificate the operator trusts (residual risk of T-244, H13), and the
// answer is validated field by field before anything is kept.
//
// # When
//
// [Service.Start] runs the checks in the background, independently of the
// start-up and of /healthz (which never contacts GitHub): the first one at
// least [Options.StartDelay] after the start, and no sooner than
// [Options.Interval] after the last attempt recorded in the database, so
// that restarts add no request; then every [Options.Interval] plus a
// random jitter. One check runs at a time; a failure is not retried before
// the next cycle, the last good result is kept and its lastError updated,
// reduced to a closed category ([Category]) with never the raw error. A
// super admin may also ask for a check ([Service.CheckNow]), at most once
// per [Options.ManualInterval] for the whole instance. With
// TT_UPDATE_CHECK=false the service makes no connection at all and writes
// nothing.
//
// The outcome is stored in the system_state table (key
// store.SystemStateUpdateCheck) as {latestVersion, releaseUrl, checkedAt,
// lastError}, and revalidated on every read: a value that does not pass
// the rules above reads as "never checked".
package updatecheck
