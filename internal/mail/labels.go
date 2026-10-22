package mail

import "github.com/ed-fr/transteira/internal/i18n"

// labels are the localized texts of the pre-rendered blocks. They are part
// of the code, not of the customizable templates: a block only exists to
// replace a condition or a loop, which templates cannot express.
type labels struct {
	colon                 string // separator before a list: ":" or " :"
	messageIntro          string
	otherChannelRecipient string
	otherChannelSender    string
	qrIntro               string
	qrAlt                 string
	sha                   string
	tooLargeLabel         string
	tooLargeText          string
	encryptedLabel        string
	encryptedText         string
	reasonTooLarge        string
	reasonEncrypted       string
	infectedIntro         string
	threat                string
	withheldIntro         string
	withheldHeading       string
	withheldNote          string
	summaryInfected       string
	summaryWithheld       string
	outcomeRejected       string
	outcomeSent           string
	adviceInfected        string
	adviceWithheld        string
	deletionScheduled     string // %s: date and time
	deletionOnce          string
}

// statusFor returns the antivirus status shown next to a delivered file.
func (l *labels) statusFor(r NotScannedReason) (label, text string) {
	switch r {
	case NotScannedTooLarge:
		return l.tooLargeLabel, l.tooLargeText
	case NotScannedEncrypted:
		return l.encryptedLabel, l.encryptedText
	}
	return "", ""
}

var allLabels = map[string]*labels{
	i18n.English: {
		colon:                 ":",
		messageIntro:          "Their message:",
		otherChannelRecipient: "This transfer is protected by a password. The password will be sent to you by another channel; it is never written in this message.",
		otherChannelSender:    "The transfer is protected by a password. Give it to the recipients through another channel (phone, text message...), never in the same e-mail as the link.",
		qrIntro:               "You can also scan this QR code to open the download page:",
		qrAlt:                 "QR code of the download link",
		sha:                   "SHA-256: ",
		tooLargeLabel:         "Not scanned by the antivirus:",
		tooLargeText:          " the file is too large or too complex to be fully analyzed.",
		encryptedLabel:        "Could not be analyzed by the antivirus:",
		encryptedText:         " encrypted archive.",
		reasonTooLarge:        "Reason: the file is too large or too complex to be fully analyzed.",
		reasonEncrypted:       "Reason: encrypted archive, whose content the antivirus cannot read.",
		infectedIntro:         "The antivirus found a threat in the following files of your transfer. They have been deleted.",
		threat:                "Detected threat: ",
		withheldIntro:         "The following files could not be analyzed by the antivirus and are withheld for safety: they cannot be downloaded.",
		withheldHeading:       "Withheld files",
		withheldNote:          "These files could not be analyzed by the antivirus and are withheld for safety: the recipients cannot download them.",
		summaryInfected:       "Infected file deleted from your transfer",
		summaryWithheld:       "File withheld from your transfer",
		outcomeRejected:       "No file of the transfer could be delivered: the transfer was not sent and the recipients have not been notified.",
		outcomeSent:           "The other files of the transfer have been sent to the recipients.",
		adviceInfected:        "Check the device the files come from with an up-to-date antivirus before sending them again.",
		adviceWithheld:        "To share a withheld file, send it again in a new transfer.",
		deletionScheduled:     "As you requested, the transfer is deleted after its first download: it will be permanently erased on %s.",
		deletionOnce:          "This notice is sent only once: later downloads are not notified.",
	},
	i18n.French: {
		colon:                 " :",
		messageIntro:          "Son message :",
		otherChannelRecipient: "Ce transfert est protégé par un mot de passe. Le mot de passe vous sera transmis par un autre canal ; il ne figure jamais dans ce message.",
		otherChannelSender:    "Le transfert est protégé par un mot de passe. Communiquez-le aux destinataires par un autre canal (téléphone, SMS...), jamais dans le même e-mail que le lien.",
		qrIntro:               "Vous pouvez aussi scanner ce QR code pour ouvrir la page de téléchargement :",
		qrAlt:                 "QR code du lien de téléchargement",
		sha:                   "SHA-256 : ",
		tooLargeLabel:         "Non analysé par l'antivirus :",
		tooLargeText:          " le fichier est trop volumineux ou trop complexe pour être entièrement analysé.",
		encryptedLabel:        "N'a pas pu être analysé par l'antivirus :",
		encryptedText:         " archive chiffrée.",
		reasonTooLarge:        "Motif : le fichier est trop volumineux ou trop complexe pour être entièrement analysé.",
		reasonEncrypted:       "Motif : archive chiffrée, dont l'antivirus ne peut pas lire le contenu.",
		infectedIntro:         "L'antivirus a détecté une menace dans les fichiers suivants de votre transfert. Ils ont été supprimés.",
		threat:                "Menace détectée : ",
		withheldIntro:         "Les fichiers suivants n'ont pas pu être analysés par l'antivirus et sont retenus par sécurité : ils ne peuvent pas être téléchargés.",
		withheldHeading:       "Fichiers retenus",
		withheldNote:          "Ces fichiers n'ont pas pu être analysés par l'antivirus et sont retenus par sécurité : les destinataires ne peuvent pas les télécharger.",
		summaryInfected:       "Fichier infecté supprimé de votre transfert",
		summaryWithheld:       "Fichier retenu dans votre transfert",
		outcomeRejected:       "Aucun fichier du transfert n'a pu être remis : le transfert n'a pas été envoyé et les destinataires n'ont pas été prévenus.",
		outcomeSent:           "Les autres fichiers du transfert ont été envoyés aux destinataires.",
		adviceInfected:        "Vérifiez l'appareil d'où proviennent les fichiers avec un antivirus à jour avant de les envoyer de nouveau.",
		adviceWithheld:        "Pour partager un fichier retenu, envoyez-le de nouveau dans un autre transfert.",
		deletionScheduled:     "Comme vous l'avez demandé, le transfert est supprimé après son premier téléchargement : il sera définitivement effacé le %s.",
		deletionOnce:          "Cet avis n'est envoyé qu'une fois : les téléchargements suivants ne sont pas signalés.",
	},
}

// labelsFor returns the labels of a supported language (rendering always
// resolves the language first).
func labelsFor(lang string) *labels {
	return allLabels[lang]
}
