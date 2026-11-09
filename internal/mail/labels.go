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
	confidentiality       string // prefix of the confidentiality level notice
	qrIntro               string
	qrAlt                 string
	sha                   string
	tooLargeLabel         string
	tooLargeText          string
	encryptedLabel        string
	encryptedText         string
	reasonTooLarge        string
	reasonEncrypted       string
	disabledLabel         string
	disabledText          string
	reasonDisabled        string
	e2eLabel              string // status label of an end-to-end encrypted file
	e2eText               string
	reasonE2E             string
	e2eFileName           string // %d: rank of the file
	shaEncrypted          string // prefix of the digest of an encrypted file
	e2eNoticeRecipient    string // key not in the mail, sent by the sender through another channel
	e2eNoticeSender       string // the sender must give the key through another channel
	e2eNotScanned         string // the files were not analyzed
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
	operatorsMailed       string
	operatorsNotMailed    string
	waitingSummary        string // %d: transfers, %d: entities
	waitingUnknown        string
	verificationNotice    string
	downloadedBy          string // prefix of the recipient notice
	downloadLinkIntro     string // intro of the download link in the sender confirmation
	personalLinks         string // sentence replacing the link when each recipient has a personal one
	linkOnlyNotice        string // sentence replacing the link of a link-only transfer
	noRecipient           string // shown instead of the recipient list of a link-only transfer without recipient
	dropLinkRecipients    string // %s: label of the drop link; shown instead of the recipient list of a drop link deposit
	dropLinkNoLabel       string // the same, the label unknown
	myTransfersIntro      string // intro of the My transfers link in the sender confirmation
	replyNotice           string // %s: date of the original transfer, entity name, sender address
	noEntity              string // shown when an administrator account is assigned to no entity yet
	setupChecked          string // setup completed with every required item done
	setupForced           string // setup completed with required items undone
	scopeCounts           string // %d: allowed IP ranges, %d: FQDN suffixes
	noExpiry              string // a provisioning token that never expires
	secretPassphrase      string // the passphrase of a secret comes from the sender through another channel
	secretFile            string // a file is attached to the secret: end-to-end encrypted, not analyzed
	secretReadSummary     string
	secretReadText        string
	secretExpiredSummary  string
	secretExpiredText     string
	secretLockedSummary   string
	secretLockedText      string
	secretRecipient       string // prefix of the recipient notice of a secret receipt
}

// statusFor returns the antivirus status shown next to a delivered file.
func (l *labels) statusFor(r NotScannedReason) (label, text string) {
	switch r {
	case NotScannedTooLarge:
		return l.tooLargeLabel, l.tooLargeText
	case NotScannedEncrypted:
		return l.encryptedLabel, l.encryptedText
	case NotScannedDisabled:
		return l.disabledLabel, l.disabledText
	case NotScannedE2E:
		return l.e2eLabel, l.e2eText
	}
	return "", ""
}

var allLabels = map[string]*labels{
	i18n.English: { //nolint:gosec // G101: mail labels named "secret...", no credential
		colon:                 ":",
		messageIntro:          "Their message:",
		otherChannelRecipient: "This transfer is protected by a password. The password will be sent to you by another channel; it is never written in this message.",
		confidentiality:       "Confidentiality level: ",
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
		disabledLabel:         "Not scanned:",
		disabledText:          " antivirus disabled.",
		reasonDisabled:        "Reason: the antivirus is disabled, so the file was not analyzed.",
		e2eLabel:              "Not scanned:",
		e2eText:               " end-to-end encrypted file, unreadable by the antivirus.",
		reasonE2E:             "Reason: the file is end-to-end encrypted, so the antivirus cannot read it.",
		e2eFileName:           "Encrypted file %d",
		shaEncrypted:          "SHA-256 of the encrypted file: ",
		e2eNoticeRecipient:    "This transfer is end-to-end encrypted. The decryption key is not in this message: the sender gives it to you through another channel. Without it the files cannot be opened.",
		e2eNoticeSender:       "This transfer is end-to-end encrypted. The recipients' e-mail contains no decryption key: give it to them through another channel (phone, text message...), never in the same e-mail as the link.",
		e2eNotScanned:         "The files were not analyzed by the antivirus (end-to-end encrypted): the server can never read them.",
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
		operatorsMailed:       "The operators of the instance have been alerted.",
		operatorsNotMailed:    "Contact the operator of the instance if the situation persists.",
		waitingSummary:        "Transfers waiting for analysis: %d; entities concerned: %d.",
		noEntity:              "no entity yet",
		setupChecked:          "Completed: every required item was done.",
		setupForced:           "Completed by force: some required items were not done.",
		scopeCounts:           "%d IP range(s), %d FQDN suffix(es)",
		noExpiry:              "never",
		secretPassphrase:      "This secret is protected by a passphrase. The sender gives it to you through another channel; it is never written in this message.",
		secretFile:            "A file is attached to this secret. It is end-to-end encrypted, so it was not analyzed by the antivirus: only open it if you trust the sender.",
		secretReadSummary:     "Your secret was read",
		secretReadText:        "Your secret was read by its recipient and has been destroyed.",
		secretExpiredSummary:  "Your secret expired unread",
		secretExpiredText:     "Your secret was not read before it expired and has been destroyed.",
		secretLockedSummary:   "Your secret was locked",
		secretLockedText:      "Too many wrong passphrases were entered: your secret was locked and destroyed without being read.",
		secretRecipient:       "Recipient: ",
		waitingUnknown:        "The number of transfers waiting could not be determined.",
		verificationNotice:    "Before downloading, you will be asked to confirm your e-mail address with a code sent to this address.",
		downloadedBy:          "Downloaded by: ",
		downloadLinkIntro:     "Download link",
		personalLinks:         "Each recipient received their own personal link.",
		linkOnlyNotice:        "No mail was sent to the recipients: share the download link that was shown to you when you sent the transfer. If you lost it, issue a new one from My transfers.",
		noRecipient:           "No recipient named.",
		dropLinkRecipients:    "The recipients of the drop link “%s” (their addresses are not disclosed).",
		dropLinkNoLabel:       "The recipients of the drop link (their addresses are not disclosed).",
		myTransfersIntro:      "Manage this transfer (delete it, extend it, see who downloaded it) in My transfers",
		replyNotice:           "This is a reply to the transfer you sent on %s. It comes from outside %s: %s proved they own this address with a code, but be careful with files you did not expect.",
	},
	i18n.French: { //nolint:gosec // G101: mail labels named "secret...", no credential
		colon:                 " :",
		messageIntro:          "Son message :",
		otherChannelRecipient: "Ce transfert est protégé par un mot de passe. Le mot de passe vous sera transmis par un autre canal ; il ne figure jamais dans ce message.",
		confidentiality:       "Niveau de confidentialité : ",
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
		disabledLabel:         "Non analysé :",
		disabledText:          " antivirus désactivé.",
		reasonDisabled:        "Motif : l'antivirus est désactivé, le fichier n'a donc pas été analysé.",
		e2eLabel:              "Non analysé :",
		e2eText:               " fichier chiffré de bout en bout, illisible par l'antivirus.",
		reasonE2E:             "Motif : le fichier est chiffré de bout en bout, l'antivirus ne peut donc pas le lire.",
		e2eFileName:           "Fichier chiffré %d",
		shaEncrypted:          "SHA-256 du fichier chiffré : ",
		e2eNoticeRecipient:    "Ce transfert est chiffré de bout en bout. La clé de déchiffrement ne figure pas dans ce message : l'expéditeur vous la transmet par un autre canal. Sans elle, les fichiers ne peuvent pas être ouverts.",
		e2eNoticeSender:       "Ce transfert est chiffré de bout en bout. L'e-mail des destinataires ne contient aucune clé de déchiffrement : transmettez-la-leur par un autre canal (téléphone, SMS...), jamais dans le même e-mail que le lien.",
		e2eNotScanned:         "Les fichiers n'ont pas été analysés par l'antivirus (chiffrés de bout en bout) : le serveur ne peut jamais les lire.",
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
		operatorsMailed:       "Les exploitants de l'instance ont été alertés.",
		operatorsNotMailed:    "Contactez l'exploitant de l'instance si la situation persiste.",
		waitingSummary:        "Transferts en attente d'analyse : %d ; entités concernées : %d.", //nolint:misspell // French text
		noEntity:              "aucune entité pour le moment",
		setupChecked:          "Terminée : tous les éléments obligatoires ont été faits.",
		setupForced:           "Terminée en forçant : certains éléments obligatoires n'ont pas été faits.",
		scopeCounts:           "%d plage(s) IP, %d suffixe(s) de FQDN",
		noExpiry:              "jamais",
		secretPassphrase:      "Ce secret est protégé par une phrase secrète. L'expéditeur vous la transmet par un autre canal ; elle ne figure jamais dans ce message.",
		secretFile:            "Un fichier est joint à ce secret. Il est chiffré de bout en bout, l'antivirus ne l'a donc pas analysé : ne l'ouvrez que si vous faites confiance à l'expéditeur.",
		secretReadSummary:     "Votre secret a été lu",
		secretReadText:        "Votre secret a été lu par son destinataire et a été détruit.",
		secretExpiredSummary:  "Votre secret a expiré sans être lu",
		secretExpiredText:     "Votre secret n'a pas été lu avant son expiration et a été détruit.",
		secretLockedSummary:   "Votre secret a été verrouillé",
		secretLockedText:      "Trop de phrases secrètes erronées ont été saisies : votre secret a été verrouillé et détruit sans avoir été lu.",
		secretRecipient:       "Destinataire : ",
		waitingUnknown:        "Le nombre de transferts en attente n'a pas pu être déterminé.", //nolint:misspell // French text
		verificationNotice:    "Avant de télécharger, il vous sera demandé de confirmer votre adresse e-mail avec un code envoyé à cette adresse.",
		downloadedBy:          "Téléchargé par : ",
		downloadLinkIntro:     "Lien de téléchargement",
		personalLinks:         "Chaque destinataire a reçu son propre lien personnel.",
		linkOnlyNotice:        "Aucun e-mail n'a été envoyé aux destinataires : transmettez-leur le lien de téléchargement qui vous a été affiché à l'envoi. Si vous l'avez perdu, générez-en un nouveau depuis Mes envois.",
		noRecipient:           "Aucun destinataire indiqué.",
		dropLinkRecipients:    "Les destinataires du lien de dépôt « %s » (leurs adresses ne sont pas communiquées).",
		dropLinkNoLabel:       "Les destinataires du lien de dépôt (leurs adresses ne sont pas communiquées).",
		myTransfersIntro:      "Gérez ce transfert (le supprimer, le prolonger, voir qui l'a téléchargé) dans Mes envois",
		replyNotice:           "Ceci est une réponse au transfert que vous avez envoyé le %s. Il provient de l'extérieur de %s : %s a prouvé posséder cette adresse par un code, mais restez prudent avec les fichiers que vous n'attendiez pas.",
	},
}

// labelsFor returns the labels of a supported language (rendering always
// resolves the language first).
func labelsFor(lang string) *labels {
	return allLabels[lang]
}
