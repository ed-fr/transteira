package mail

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/ed-fr/transteira/internal/i18n"
)

// abuseLabels are the localized sentences of the abuse mails. Like the
// labels of the blocks, they are part of the code, not of the customizable
// templates.
type abuseLabels struct {
	// rules maps a rule to its sentence, with indexed verbs: %[1]s is the
	// value, %[2]s the threshold.
	rules          map[string]string
	externalBytes  string // external_quota with sizes
	offHoursNoTime string // off_hours without time
	genericRule    string
	blocked        string
	notBlocked     string
	invitations    string // notice of the invitations rule, blocked or not
	categories     map[string]string
	reporterVerif  string // %s: address
	reporterLink   string // %d: recipient number
	reporterShared string
}

var allAbuseLabels = map[string]*abuseLabels{
	i18n.English: {
		rules: map[string]string{
			AbuseRuleDailyBytes:     "Daily volume threshold exceeded: %[1]s sent, threshold %[2]s.",
			AbuseRuleDailyTransfers: "Daily transfer threshold exceeded: %[1]s transfers, threshold %[2]s.",
			AbuseRuleRecipients:     "Too many recipients in one transfer: %[1]s recipients, threshold %[2]s.",
			AbuseRuleUnusualVolume:  "Unusual volume: about %[1]s times the usual daily volume of this sender.",
			AbuseRuleLargeExternal:  "Large transfer to external addresses: %[1]s, threshold %[2]s.",
			AbuseRuleOffHours:       "Transfer sent outside office hours, at %[1]s.",
			AbuseRuleInvitations:    "Invitation limit reached: %[1]s invitations, limit %[2]s.",
			AbuseRuleExternalQuota:  "Deposit quota of the external users reached: %[1]s deposits, limit %[2]s.",
		},
		externalBytes:  "Deposit quota of the external users reached: %[1]s deposited, limit %[2]s.",
		offHoursNoTime: "Transfer sent outside office hours.",
		genericRule:    "An abuse detection threshold was reached.",
		blocked:        "The transfer was refused.",
		notBlocked:     "The transfer was not blocked: this is an alert only.",
		invitations:    "Further invitations from this user are refused for the rest of the rolling hour.",
		categories: map[string]string{
			AbuseCategoryMalware:        "Malware",
			AbuseCategoryPhishing:       "Phishing",
			AbuseCategoryIllegalContent: "Illegal content",
			AbuseCategorySpam:           "Spam",
			AbuseCategoryUnknownSender:  "Unknown sender",
			AbuseCategoryOther:          "Other",
		},
		reporterVerif:  "Reported by %s, whose address was verified by a code.",
		reporterLink:   "Reported via the link of recipient #%d, unverified.",
		reporterShared: "Reported via the shared link of the transfer, unverified.",
	},
	i18n.French: {
		rules: map[string]string{
			AbuseRuleDailyBytes:     "Seuil de volume quotidien dépassé : %[1]s envoyés, seuil %[2]s.",
			AbuseRuleDailyTransfers: "Seuil quotidien de transferts dépassé : %[1]s transferts, seuil %[2]s.", //nolint:misspell // French text
			AbuseRuleRecipients:     "Trop de destinataires dans un transfert : %[1]s destinataires, seuil %[2]s.",
			AbuseRuleUnusualVolume:  "Volume inhabituel : environ %[1]s fois le volume quotidien habituel de cet expéditeur.",
			AbuseRuleLargeExternal:  "Gros envoi vers des adresses externes : %[1]s, seuil %[2]s.",
			AbuseRuleOffHours:       "Transfert envoyé en dehors des heures de bureau, le %[1]s.",
			AbuseRuleInvitations:    "Limite d'invitations atteinte : %[1]s invitations, limite %[2]s.",
			AbuseRuleExternalQuota:  "Quota de dépôt des externes atteint : %[1]s dépôts, limite %[2]s.",
		},
		externalBytes:  "Quota de dépôt des externes atteint : %[1]s déposés, limite %[2]s.",
		offHoursNoTime: "Transfert envoyé en dehors des heures de bureau.",
		genericRule:    "Un seuil de détection des abus a été atteint.",
		blocked:        "Le transfert a été refusé.",
		notBlocked:     "Le transfert n'a pas été bloqué : il s'agit d'une simple alerte.",
		invitations:    "Les nouvelles invitations de cet utilisateur sont refusées jusqu'à la fin de l'heure glissante.",
		categories: map[string]string{
			AbuseCategoryMalware:        "Logiciel malveillant",
			AbuseCategoryPhishing:       "Hameçonnage",
			AbuseCategoryIllegalContent: "Contenu illicite",
			AbuseCategorySpam:           "Courrier indésirable",
			AbuseCategoryUnknownSender:  "Expéditeur inconnu",
			AbuseCategoryOther:          "Autre",
		},
		reporterVerif:  "Signalé par %s, dont l'adresse a été vérifiée par un code.",
		reporterLink:   "Signalé via le lien du destinataire n° %d, non vérifié.",
		reporterShared: "Signalé via le lien partagé du transfert, non vérifié.",
	},
}

// abuseLabelsFor returns the abuse labels of a supported language, English
// for any other.
func abuseLabelsFor(lang string) *abuseLabels {
	if l, ok := allAbuseLabels[lang]; ok {
		return l
	}
	return allAbuseLabels[i18n.English]
}

// formatNumber formats a count or a factor, with one decimal at most, the
// way lang writes it. A NaN or infinite value is shown as 0.
func formatNumber(lang string, v float64) string {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		v = 0
	}
	s := strconv.FormatFloat(math.Round(v*10)/10, 'f', -1, 64)
	if lang == i18n.French {
		s = strings.Replace(s, ".", ",", 1)
	}
	return s
}

// formatBytesFloat formats a size given as a float with [FormatSize],
// saturating at the int64 range.
func formatBytesFloat(lang string, v float64) string {
	switch {
	case math.IsNaN(v) || v < 0:
		v = 0
	case v >= math.MaxInt64:
		v = math.MaxInt64 - 1024
	}
	return FormatSize(lang, int64(v))
}

// abuseRuleSentence returns the localized sentence describing d, a generic
// one for an unknown rule.
func abuseRuleSentence(lang string, d AbuseAlertData) string {
	l := abuseLabelsFor(lang)
	size := func(v float64) string { return formatBytesFloat(lang, v) }
	num := func(v float64) string { return formatNumber(lang, v) }
	switch d.Rule {
	case AbuseRuleDailyBytes, AbuseRuleLargeExternal:
		return fmt.Sprintf(l.rules[d.Rule], size(d.Value), size(d.Threshold))
	case AbuseRuleDailyTransfers, AbuseRuleRecipients, AbuseRuleInvitations:
		return fmt.Sprintf(l.rules[d.Rule], num(d.Value), num(d.Threshold))
	case AbuseRuleExternalQuota:
		if d.Bytes {
			return fmt.Sprintf(l.externalBytes, size(d.Value), size(d.Threshold))
		}
		return fmt.Sprintf(l.rules[d.Rule], num(d.Value), num(d.Threshold))
	case AbuseRuleUnusualVolume:
		return fmt.Sprintf(l.rules[d.Rule], num(d.Value))
	case AbuseRuleOffHours:
		if d.At.IsZero() {
			return l.offHoursNoTime
		}
		return fmt.Sprintf(l.rules[d.Rule], FormatDateTime(lang, d.At))
	}
	return l.genericRule
}

// abuseAlertValues returns the variables of the abuse_alert template from
// an AbuseAlertData.
func abuseAlertValues(_ *labels, lang string, data any) (map[string]value, bool) {
	d, ok := data.(AbuseAlertData)
	if !ok {
		return nil, false
	}
	l := abuseLabelsFor(lang)
	notice := l.notBlocked
	switch {
	case d.Rule == AbuseRuleInvitations:
		// The invitation limit always refuses, whatever blockOnExceed says.
		notice = l.invitations
	case d.Blocked:
		notice = l.blocked
	}
	return map[string]value{
		"tenant_name":    textValue(d.TenantName),
		"sender_email":   textValue(d.SenderEmail),
		"rule_summary":   textValue(abuseRuleSentence(lang, d)),
		"day":            textValue(d.Day),
		"blocked_notice": noticeBlock(true, notice, true),
		"admin_link":     urlValue(d.AdminLink),
	}, true
}

// abuseReportValues returns the variables of the abuse_report template from
// an AbuseReportData.
func abuseReportValues(lb *labels, lang string, data any) (map[string]value, bool) {
	d, ok := data.(AbuseReportData)
	if !ok {
		return nil, false
	}
	l := abuseLabelsFor(lang)
	category, known := l.categories[d.Category]
	if !known {
		category = l.categories[AbuseCategoryOther]
	}
	var reporter string
	switch {
	case d.ReporterEmail != "":
		reporter = fmt.Sprintf(l.reporterVerif, d.ReporterEmail)
	case d.RecipientIndex > 0:
		reporter = fmt.Sprintf(l.reporterLink, d.RecipientIndex)
	default:
		reporter = l.reporterShared
	}
	return map[string]value{
		"tenant_name":      textValue(d.TenantName),
		"transfer_id":      textValue(d.TransferID),
		"sender_email":     textValue(d.SenderEmail),
		"category":         textValue(category),
		"reporter_notice":  textValue(reporter),
		"reporter_message": messageBlock(lb, d.Message),
		"admin_link":       urlValue(d.AdminLink),
	}, true
}
