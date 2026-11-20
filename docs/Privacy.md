# Phoenix Privacy Policy

**Version 2026-11-20. Effective 20 November 2026.**

This policy explains what personal data the Phoenix desktop application and its online services handle, why, and what choices you have. Phoenix is provided by Drakes Software Solutions LLC ("Phoenix", "we", "us"), which is responsible for the data described here. It goes with the [Terms of Service](Terms.md).

Phoenix is a security product: several of its features work by observing your device or carrying your traffic. We have tried to be specific about what each one involves.

## 1. The short version

- Personal data about you and your devices is only sent once you sign in. Before that, the application only downloads what it needs to run: updates, the security agent package, and antivirus signatures.
- Each feature (VPN, antivirus, endpoint monitoring, AI assistant) only handles data once you turn it on.
- Conversations with the AI assistant are end-to-end encrypted between this application and the assistant.
- Usage telemetry from the application is switched off by default.
- We do not sell your personal data, and we do not use it for advertising.

## 2. What we handle, feature by feature

### Your account and sign-in

When you sign in, Phoenix handles your account identifier, your email address and profile details from your Phoenix account, and the session credentials issued to this device. Each signed-in device is recorded with a device identifier, a display name that includes the computer's name and operating system (for example "Phoenix Desktop · Alex-MacBook (macOS)"), the application version, the time it signed in and was last active, and the IP address it connected from.

Your session credentials are stored on your device, encrypted, with the key held in your operating system's keychain or credential store.

### VPN

To set up the VPN the application creates an encryption key pair on your device and sends us the **public** key and the computer's name. The private key never leaves your device. We return a configuration containing the VPN address assigned to this device.

While the VPN is connected, your device's internet traffic passes through Phoenix VPN servers. Operating the VPN necessarily involves the IP address you connect from, the VPN address assigned to you, and connection information such as when a device connected and how much data it transferred.

### Antivirus

Scanning happens on your device. Files are not uploaded to us for scanning. The application downloads virus signature updates from the ClamAV project's servers, which see your IP address as any download server does.

If you also turn on endpoint monitoring, antivirus detections (the file path, the name of the detected threat and the time) are sent to the monitoring service as security events.

### Endpoint monitoring

When you install the security agent, your device is enrolled in the Phoenix monitoring service under a name made of the computer's name and part of a hardware identifier, so that the same computer is recognised if Phoenix is reinstalled.

The agent then sends security-relevant information from your device to the monitoring service. This can include: operating system and software inventory, including installed packages and their versions; known vulnerabilities affecting that software; running processes and network connections; security configuration; system and security logs; changes to monitored files; and, on Windows, process, network and file activity recorded by Microsoft Sysmon and events from Microsoft Defender. These events can contain user names, file names and paths, command lines, and IP addresses.

This is the most detailed data Phoenix collects. It is used to detect threats, show you the security state of your devices, and produce alerts.

### Device management and security posture

The application retrieves the list of devices on your account and a summary of their security state (for example whether antivirus is running and whether updates are missing) so it can show them to you. Removing a device in the application ends its session and removes its VPN access.

### AI assistant

Messages you send to the assistant, and its replies, travel over an end-to-end encrypted channel between this application and the Phoenix assistant. To answer questions about your devices, the assistant uses the security data described above for your account. If you type the code of a recent action (for example `PX-4K7Q`), the local details of that action are attached to that one message.

Alerts from the monitoring service are delivered to the application over the same encrypted channel.

Your conversation history is stored on your device and is removed when you sign out. If you change the assistant's connection in Settings to a different service of your choosing, your messages go to that service instead, under its own terms.

### Diagnostics and logs

The application keeps a log file and a short history of recent actions on your device, to help with troubleshooting. They stay on your device unless you choose to share them. "Copy diagnostics" in Settings produces a report with secrets removed, which you can read before sending it to anyone.

Automatic telemetry from the application is off by default. If it is switched on, application log records, which can include the computer's name, user name and file paths, are sent to a Phoenix collector over an encrypted connection.

### Updates and downloads

The application contacts Phoenix servers to check for updates and to download the security agent, and may fetch the list of optional plugins from the Phoenix plugin catalogue. These requests include the application version, your operating system, and your IP address.

## 3. Why we use this data

We use the data described above to:

- provide the features you turn on, and keep them working;
- authenticate you and protect your account;
- detect, investigate and alert you to security threats on your devices;
- operate, secure and troubleshoot the Service, including preventing abuse;
- meet legal obligations.

Where the law requires a legal basis: we process this data to perform our agreement with you, on the basis of our legitimate interest in running a secure and reliable service, to comply with legal obligations, and, where applicable, on the basis of your consent, which you can withdraw by turning the feature off.

We do not use your data to build advertising profiles, and we do not make decisions about you by automated means that have legal or similarly significant effects.

## 4. Who receives it

- **Service providers** that host and deliver the Service for us, such as infrastructure, network and security providers. They may process data only on our instructions.
- **Your organisation**, if your account was set up by one: its administrators may be able to see the security state and alerts for the devices on that account.
- **Authorities**, where we are legally required to disclose data, or where it is necessary to protect the rights, safety or security of people or of the Service.
- **A successor**, if the business is reorganised or transferred, subject to this policy.

We do not sell personal data, and we do not share it for cross-context behavioural advertising.

## 5. Where it is processed

Our servers and service providers may be in a different country from you, including the United States. Where personal data is transferred across borders we rely on the safeguards the applicable law requires.

## 6. How long we keep it

We keep account and device records for as long as your account exists, and security events and alerts for as long as they are needed to provide monitoring and to investigate incidents. After that, and when your account is closed, data is deleted or anonymised, except where we need to keep it for legal, security or dispute-resolution reasons.

On your device, signing out removes your session credentials, VPN configuration and keys, chat history and agent enrolment. Uninstalling Phoenix removes its local data.

## 7. Security

Session credentials and other secrets are encrypted on your device. Connections to Phoenix services use TLS. Assistant conversations and alerts are end-to-end encrypted. VPN private keys are generated on, and never leave, your device. Updates and downloaded components are verified with digital signatures before they are installed.

No system is perfectly secure. If we become aware of a breach affecting your personal data, we will notify you as the law requires.

## 8. Your choices and rights

- **In the application:** turn any feature on or off; remove a device from your account under Devices → Sessions; sign out; uninstall.
- **Your rights:** depending on where you live, you may have the right to access, correct, delete or export your personal data, to restrict or object to its processing, and to withdraw consent. You will not be treated differently for exercising these rights. To make a request, contact us at the address below; we may need to verify that the request comes from you. You may also have the right to complain to your local data protection authority.

If your account was set up by an organisation, we may refer your request to that organisation.

## 9. Children

Phoenix is not intended for children. We do not knowingly collect personal data from anyone under 16. If you believe a child has given us personal data, contact us and we will delete it.

## 10. Changes to this policy

We may update this policy. When we make a change that matters, the application will show you the new version and ask you to accept it before you sign in again. The version date at the top tells you which version you are reading.

## 11. Contact

Drakes Software Solutions LLC
Email: info@phoenix.exposed
