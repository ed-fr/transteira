# Sending files

This service lets you send large files to one or more people: each recipient receives an email with a download link. The files are stored encrypted on the server and deleted automatically when the transfer expires. There is no account to create. Internal users of the organisation send files directly; an external person needs an invitation.

## Who can send files

Sending depends on where you connect from and on your email address.

You are an *internal user* when **both** conditions are met:

- you are connected from your organisation's network;
- your email address belongs to one of your organisation's email domains.

If one of these conditions is missing, the deposit is refused with the message **Deposits are only possible from the internal network with an address of the organisation. To send files from outside, ask an internal user to invite you.**

An external person (outside the network or with another email address) needs an invitation from an internal user: see [Sending files with an invitation](topic:invitation).

> **Note** Your administrator may also have blocked some addresses or domains. A blocked address cannot send files.

<!-- topic: deposit -->
## Sending files

Sending files takes four steps, described in detail below:

1. [Identify yourself](topic:deposit-identify) with a code received by email.
1. [Fill in the transfer](topic:deposit-options): recipients, message, duration, options and files.
1. [Follow the upload](topic:deposit-upload) of your files.
1. Wait for the [antivirus analysis](topic:deposit-antivirus): the recipients are then notified by email.

What your recipients see is described in [Downloading the files](topic:download).

<!-- topic: deposit-identify -->
### Identifying yourself with a code

This step proves that the email address you enter is really yours.

Enter **Your email address**, then click **Continue**.

![Sending page with the field Your email address filled in and the Continue button](../screenshots/en/deposit-email.png)

A 6-digit code is sent to that address. If you do not see it after a minute or two, look in your spam folder. Type the code in **Verification code**, then click **Verify**.

![Step Enter the verification code, with the Verification code field and the Verify, Send a new code and Use another address buttons](../screenshots/en/deposit-code.png)

A few rules apply to the codes:

- a code is valid for 15 minutes; the page shows **The code is valid until** followed by the time;
- after 2 wrong entries, the code no longer works: click **Send a new code** to receive another one;
- you can receive at most 5 codes per hour for the same address, and 20 per hour from the same network address;
- if you made a typo in your address, click **Use another address**.

You do not have to enter a code every time. As an internal user, once you have entered a code on a browser, that browser remembers you. A code is asked again on another computer or another browser, after 12 months without using the service, and always when you send files with an invitation.

Once you are identified, the top of the page shows **Identified as** followed by your address, and an **End session** button. Click it when you have finished, especially on a shared computer. The session also ends by itself after a few hours (4 hours unless your organisation chose otherwise); the page then shows **Your session has expired. Identify yourself again to continue.**

<!-- topic: deposit-options -->
### Filling in the transfer

The **New transfer** form describes what you send, to whom and for how long.

![New transfer form with a recipient, a message, the duration 7 days selected and the Password field](../screenshots/en/deposit-form.png)

Fill in the fields:

- **Recipients**: one or more email addresses, separated by commas or line breaks. If you enter too many, the form tells you the maximum.
- **Message**: optional. It is sent to the recipients with the link.
- **Available for**: **1 day**, **7 days** or **30 days**. The period starts when the transfer becomes available, that is after the antivirus analysis.
- **Password**: optional, with no complexity rule. Send it to the recipients through another channel (phone, text message), never in the same email. After 3 wrong passwords, the transfer is locked for 15 minutes.
- **Delete the transfer after the first download**: the transfer is deleted, for all recipients, once one of them has downloaded all the files, either as one ZIP archive or file by file. The deletion happens a few minutes later.
- **Files to send**: drag your files onto the area **Drag and drop files here, or** click **choose files**. To remove a file from the list, use the remove button next to its name. Under the list, the form shows **Total:** followed by the size of your files and the size allowed.

A transfer can contain up to 20 GB in total; your organisation may have set a lower limit. The hint under **Files to send** shows the actual limits (total size and number of files).

> **Note** Folders cannot be sent as such. Select the files inside the folder, or compress the folder into a ZIP file yourself and send that file.

When everything is ready, click **Send**.

<!-- topic: deposit-upload -->
### Following the upload

While your files are being sent, the page shows how far the upload has gone.

The **Overall progress** bar shows the whole transfer, and each file has its own progress line.

If the connection drops, the upload tries again by itself (**Connection lost, trying again…**). You can also stop it with **Pause** and continue later with **Resume**: the upload continues where it stopped, without starting again from the beginning.

If you leave the page during the upload, the browser asks you to confirm, because leaving interrupts the upload. If the page was closed or reloaded anyway, come back to the sending page on the same browser while your session lasts. The page shows **Resume the interrupted upload**: select the same files again, then click **Continue the upload**. An unfinished upload is discarded after a while without activity (24 hours unless your organisation chose otherwise).

To give up, click **Cancel the transfer** and confirm: the files already sent are deleted.

<!-- topic: deposit-antivirus -->
### Antivirus analysis and confirmation

Before your recipients are notified, every file is checked by an antivirus.

When the upload is finished, the page shows **Analysing the files**. You can close the page: you will receive an email when the transfer is ready.

![Summary Transfer sent with the recipients notified, the expiry date and, for each file, its antivirus status and SHA-256 fingerprint](../screenshots/en/deposit-sent.png)

The summary **Transfer sent** lists the **Recipients notified**, the expiry date (**Available until**), a reminder to send the password if you set one, and for each file its antivirus result and SHA-256 fingerprint, with a **Copy** button.

The *SHA-256 fingerprint* is a code calculated from the content of the file: your recipients can use it to check that their copy is identical to yours.

Each file gets one of these antivirus results:

- **no threat found**: the file is delivered;
- **threat detected, file deleted**: the file is not delivered and you receive an alert by email;
- **not analysed (file too large)** or **not analysed (encrypted archive)**: the file is delivered, you are told by email and the recipients are warned on the download page;
- **analysis failed, file withheld**: the file is not delivered.

If no file at all can be delivered, the page shows **Transfer refused** and the recipients are not notified.

By email, you also receive a confirmation of sending and a notice of the first download (only the first one).

> **Note** The download link is not shown on the screen: the recipients receive it by email, with a QR code to open it on a phone and the fingerprints of the files.

<!-- topic: invite -->
## Inviting an external person

An invitation lets someone outside your organisation send you files.

Only internal users identified on the sending page can invite. Once identified, click **Invite someone to send you files** at the top of the page.

![Invite an external person form with the email address of the person, an optional message and the language of the invitation email](../screenshots/en/invite.png)

Fill in the form:

1. Enter the **Email address of the person to invite**.
1. Add a **Message** if you wish (optional). It is included in the invitation email.
1. Choose the **Language of the invitation email**.
1. Click **Send the invitation**.

The page confirms with **Invitation sent**. You can then click **Invite another person** or **Back to sending files**.

The files the person sends are addressed to you. The invitation link stays valid for 12 months if it is not used; each time it is used, it remains valid for 12 more months. You can send up to 20 invitations per hour; beyond that, the page shows **You have sent too many invitations in the last hour.**

If the page shows **Identify yourself first**, go back to the sending page and identify yourself. If it shows **Invitations not available**, you are not recognised as an internal user.

Your administrator can revoke an invitation at any time.

<!-- topic: invitation -->
## Sending files with an invitation

This section is for external people who received an invitation email.

Open the link in the email. The page **You are invited to send files** shows who invited you (**Invited by**), the address the invitation was sent to, the date until which it is valid (**Invitation valid until**) and the message of the person who invited you.

![Page You are invited to send files with the person who invited you, your email address, the validity date and the message](../screenshots/en/invitation-landing.png)

Click **Continue**. You then [identify yourself with a code](topic:deposit-identify), using the address the invitation was sent to (it is already filled in). With an invitation, a code is asked every time.

The form then shows **The files will be sent to** followed by the address of the person who invited you: there is no recipient to enter. The rest of the form works as described in [Filling in the transfer](topic:deposit-options).

If the link does not work:

- **Invitation not found**: the link is incomplete. Copy it entirely from the email, or click it directly.
- **Invitation expired**: the invitation is no longer valid. Ask the person who invited you to send a new one.

<!-- topic: deposit-problems -->
## Common problems

Here are the messages you may meet, and what to do.

- **Deposits are only possible from the internal network with an address of the organisation…**: connect from the organisation's network, or ask an internal user to invite you.
- The code does not arrive: look in your spam folder, wait a minute, then click **Send a new code** (within the hourly limits).
- **The files exceed the maximum size of a transfer. Remove some files.**: remove files, or send them in several transfers.
- **1 file name is not accepted: rename the file and add it again.** (or several): rename the file on your computer, then add it again.
- **The storage space of this service is full. Try again later.**: try again later, or contact your administrator.
- **Some files are not accepted by this service.**: your organisation has blocked these files; contact your administrator if you think it is a mistake.
- **Your session has expired. Identify yourself again, then select the same files to resume.**: the upload then continues where it stopped.

<!-- topic: maintenance -->
## Service under maintenance

The service is sometimes stopped briefly for an update.

The page **Service under maintenance** is shown: new transfers and invitations are suspended, but downloads remain available. An upload in progress is paused and resumes after the maintenance. Come back later.

![Page Service under maintenance with a message from the administrator](../screenshots/en/maintenance.png)

<!-- topic: legal -->
## Legal information

Your organisation writes the legal documents of the service.

At the bottom of the page, the links **Legal notice** and **Privacy policy** open these documents (a link appears only when the document has been written). If a document is missing, the page shows **This document has not been published by this service.**

![Legal notice page of the entity, with the footer links Legal notice and Help and the Language list](../screenshots/en/legal-notice.png)

The service uses only technical cookies, with no audience measurement. The footer also holds the **Language** list and a **Help** link to the help of the current screen.
