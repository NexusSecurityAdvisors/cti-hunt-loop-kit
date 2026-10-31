# Playbook HL-0011 — OAuth Illicit Consent Grant

| Field | Value |
|---|---|
| Hypothesis ID | HL-0011 |
| ATT&CK | **T1528** Steal Application Access Token · related: **T1550.001** Use Alternate Authentication Material: Application Access Token |
| Tactic(s) | Credential Access, Lateral Movement |
| Platforms | Microsoft Entra ID / Microsoft 365 |
| Difficulty | Intermediate — needs Entra audit and sign-in logs and an understanding of delegated vs. application permissions |
| Queries | [Sigma](../queries/sigma/hl-0011_oauth_consent_abuse.yml) · [KQL](../queries/kql/hl-0011_oauth_consent_abuse.kql) · [SPL](../queries/spl/hl-0011_oauth_consent_abuse.spl) |

---

## 1. Intelligence basis

In an illicit consent grant (consent phishing), the adversary registers a multi-tenant application with a harmless-sounding name and gets a user to click **Accept** on the Microsoft consent prompt. The application then holds OAuth tokens for the user's mailbox and files without ever needing the password again. It is attractive because:

- The consent is a legitimate Entra ID operation: no malware, no exploit, and the sign-in that follows comes from the application, not the user.
- With `offline_access` the app receives a **refresh token**. Resetting the user's password or re-registering MFA does **not** revoke the grant; the app keeps reading mail until the grant is removed or the service principal is disabled.
- Scopes such as `Mail.Read`, `Mail.Send`, `Files.Read.All` and `MailboxSettings.ReadWrite` give exactly what business email compromise and lure crafting need: invoice threads, contacts, inbox rules.
- It often follows an account takeover (see HL-0012): the attacker signs in as the victim from their own infrastructure and consents to their own app, turning a short-lived session into durable access.

Cite the specific report or advisory that motivates the hunt in your hypothesis card.

## 2. Hypothesis

> If an adversary has obtained token-based access through an illicit consent grant, we expect to see **successful "Consent to application" events with mailbox, file or directory scopes** in Entra ID audit logs, granted by a **regular user (not admin consent)** to an **unverified or newly created application**, often from an **IP address the user does not normally sign in from**, during the last 14–30 days.

**Refuted if:** Entra audit logs cover the full window, user consent is restricted to verified publishers and low-risk scopes for the whole period, and every high-risk consent maps to an approved application with a change record.

## 3. Data sources

| Source | Event / table | Key fields |
|---|---|---|
| Entra ID audit logs | `AuditLogs` (Sentinel) / `azure:aad:audit` (Splunk) — *Consent to application*, *Add service principal*, *Add delegated permission grant* | `InitiatedBy.user.userPrincipalName`, `InitiatedBy.user.ipAddress`, `TargetResources[0].displayName` / `.id`, `modifiedProperties`: `ConsentAction.Permissions`, `ConsentContext.IsAdminConsent` |
| Entra ID sign-in logs | `SigninLogs` (user), `AADServicePrincipalSignInLogs` (app) | `UserPrincipalName`, `IPAddress`, `Location`, `ResultType`, `AppId` |
| Microsoft Graph / Entra admin center | Service principal and app registration | `verifiedPublisher`, publisher domain, `createdDateTime`, reply URLs, owners |
| Microsoft Defender for Cloud Apps | OAuth apps page, app governance, `CloudAppEvents` | Permission level, community use, app activity (mail read, files accessed) |
| Exchange Online | `OfficeActivity` / unified audit log (`MailItemsAccessed`) | Which messages the app actually read |

**Pre-check:** confirm Entra diagnostic settings stream **AuditLogs and SigninLogs** to your SIEM and retention covers the window. The default portal retention is short (7 days on Entra ID Free, 30 on P1/P2). Without audit logs, record the outcome as **Inconclusive (data gap)** and fall back to a current-state review of all OAuth grants (Graph `oauth2PermissionGrants`, Defender for Cloud Apps).

## 4. Hunt steps

1. **Run the query** for your platform. It keeps successful *Consent to application* events whose scopes contain a high-risk permission, mirroring the Sigma rule, and parses the scope string and admin-consent flag out of `modifiedProperties`.
2. **Separate admin consent from user consent.** Admin consent (`IsAdminConsent = True`, `ConsentType: AllPrincipals`) should map to a change record. User consent to mailbox or file scopes is the primary lead, especially if your consent policy should have blocked it.
3. **Check app age.** The query joins the *Add service principal* event for the same app. An app that first appeared in the tenant minutes before the consent was created by that consent flow: a new, unknown multi-tenant app.
4. **Stack by application.** `AppConsentingUsers` counts distinct users consenting to the same app (any scope). One user consenting to a never-seen app is rarer, and more interesting, than a tool half the company uses.
5. **Pivot on the consenting session.** Take `ConsentIp` into `SigninLogs`: is it the user's normal egress? `IpDaysSeen` counts days of successful sign-ins from that IP; 0 or 1 means new. Look at what happened just before: MFA denials, a password spray, an impossible-travel alert (HL-0012).
6. **Check the publisher.** In the Entra admin center (Enterprise applications) or Graph, look at `verifiedPublisher`, publisher domain, reply URLs and owners. Unverified publisher + generic name + external reply URL is the classic pattern.
7. **Compare scopes with the app's stated purpose.** A "viewer", "PDF", or "invoice" app has no reason to read all mail and all files.
8. **Measure impact.** Query `AADServicePrincipalSignInLogs` for the app's own sign-ins and `MailItemsAccessed` / file events for what it touched after the grant. Search for the same app ID across all tenants you manage.
9. **Classify** each consent and record it in the hunt report.

## 5. Known benign sources (tune, don't ignore)

| Source | How to recognize |
|---|---|
| Approved backup, archiving, or e-discovery tools | Admin consent by a known admin, verified publisher, change ticket, consent from corporate egress, app present for a long time |
| Line-of-business apps registered in your own tenant | Single-tenant app, owners are your staff, documented in the app inventory |
| Verified-publisher productivity add-ins | Many users, consistent low-risk scopes; high-risk scopes only through the admin consent workflow |
| Admin consent workflow approvals | Consent preceded by an approved request in the admin consent workflow log |

Scope exclusions to **app ID + scopes + consent type**. Excluding by app display name lets an attacker reuse a trusted name.

## 6. Triage questions

- Was this admin consent or user consent? If user consent, should your consent policy have allowed it at all?
- Is the publisher verified? Is the app single-tenant (yours) or multi-tenant (someone else's)?
- How old is the app in your tenant? Was the service principal created minutes before the consent?
- Was the consenting session from the user's normal IP and country, or from a new IP that also shows MFA denials or a risky sign-in?
- Do the scopes match the app's stated purpose? Does it request `offline_access` together with mail or file scopes?
- Has the app signed in and used the grant since (mail read, files listed, inbox rules created)?

## 7. Operationalize

- Promote the Sigma rule with exclusions for documented app IDs from step 5; raise severity when consent type is user, the app is new, and the consenting IP is new for the user.
- **Restrict user consent** to apps from **verified publishers** requesting **low-risk permissions** you classify (Entra ID: Enterprise applications > Consent and permissions), or disable user consent entirely.
- Enable the **admin consent workflow** so users can request high-risk apps instead of being blocked silently.
- Use **Microsoft Defender for Cloud Apps** OAuth app policies and **app governance** to alert on high-privilege, rare, or unverified apps and on unusual app activity.
- On confirmation: **revoke the OAuth2 permission grants**, **disable the service principal** (or delete it), revoke the user's sessions, and review mailbox rules and forwarding. A password reset alone does **not** revoke the app's refresh token.
- Record outcome, detections, and data gaps in `templates/hunt-report.md` and `templates/intel-feedback.md`.

## Lab notes

- The lab contains five days of Entra ID audit logs and sign-in logs, in both a flattened form (`data/lab/entra/`) and Sentinel schema (`data/lab/sentinel/AuditLogs.csv`, `SigninLogs.csv`). In the Sentinel files, scopes and the admin-consent flag live inside the `TargetResources` JSON.
- Several popular apps are consented to by many users; their scopes are low-risk and the query filters them. Confirm you agree with that.
- Expect two high-risk consents. One needs a change ticket to close; the other does not look like anything your users should be doing.
- The sign-in pivot will not return history for every consenting account. Decide whether that is suspicious or simply how that account works.
- Look at the audit events right before the suspicious consent, and at the sign-in logs right before that. This hunt and HL-0012 are two halves of the same story.

## References

Current threat intelligence and research (full list in [`docs/REFERENCES.md`](../docs/REFERENCES.md)):

- Microsoft Threat Intelligence (2024). *Midnight Blizzard: Guidance for responders on nation-state attack*. Microsoft Security Blog. <https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/> ([bib](../docs/REFERENCES.md#ms-midnight-blizzard-2024))

Technique and product documentation:

- MITRE ATT&CK T1528 — https://attack.mitre.org/techniques/T1528/
- MITRE ATT&CK T1550.001 — https://attack.mitre.org/techniques/T1550/001/
- Microsoft: Detect and remediate illicit consent grants — https://learn.microsoft.com/en-us/defender-office-365/detect-and-remediate-illicit-consent-grants
- Microsoft: Configure how users consent to applications — https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent
- SigmaHQ rule repository — https://github.com/SigmaHQ/sigma
