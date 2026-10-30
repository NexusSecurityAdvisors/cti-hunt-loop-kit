# Playbook HL-0012 — MFA Fatigue / Push Bombing

| Field | Value |
|---|---|
| Hypothesis ID | HL-0012 |
| ATT&CK | **T1621** Multi-Factor Authentication Request Generation · related: **T1078.004** Valid Accounts: Cloud Accounts |
| Tactic(s) | Credential Access, Initial Access |
| Platforms | Microsoft Entra ID / Microsoft 365 |
| Difficulty | Beginner — one table, one error code, one join |
| Queries | [Sigma](../queries/sigma/hl-0012_mfa_fatigue.yml) · [KQL](../queries/kql/hl-0012_mfa_fatigue.kql) · [SPL](../queries/spl/hl-0012_mfa_fatigue.spl) |

---

## 1. Intelligence basis

Once an adversary has a valid password (phishing, infostealer logs, password reuse), push-based MFA is often the last barrier. MFA fatigue, or push bombing, beats it by sending prompt after prompt, often late at night, until the user approves one to make it stop or because a "help desk" caller asked them to. The technique has featured in several well-publicized intrusions by extortion groups and is cheap to run:

- Each sign-in attempt with the stolen password generates a fresh push notification; scripting dozens per hour is trivial.
- In Entra ID every rejected or unanswered prompt is logged as **ResultType 500121** (*Authentication failed during strong authentication request*); the approval is a **ResultType 0** success for the same user, usually from the **same attacker IP**.
- The resulting session is a legitimate, MFA-satisfied cloud login (T1078.004), so everything that follows (mailbox access, OAuth consent, see HL-0011) looks like the user.

Cite the specific report or advisory that motivates the hunt in your hypothesis card.

## 2. Hypothesis

> If an adversary is using MFA fatigue against our users, we expect to see **bursts of MFA denials (ResultType 500121) for a single user within one hour**, followed **within an hour by a successful sign-in** for the same user, typically from the **same IP as the denials**, an IP **outside corporate ranges**, or a **country new for that user**, in Entra ID sign-in logs during the last 14–30 days.

**Refuted if:** sign-in logs cover the window, and every user with a burst of denials has a documented benign explanation (device replacement, enrollment problem) with no success from a non-corporate IP afterward.

## 3. Data sources

| Source | Event / table | Key fields |
|---|---|---|
| Entra ID sign-in logs | `SigninLogs` (Sentinel) / `azure:aad:signin` (Splunk) | `UserPrincipalName`, `ResultType` (string in Sentinel), `IPAddress`, `Location`, `AppDisplayName`, `AuthenticationDetails` |
| Defender XDR Advanced Hunting | `AADSignInEventsBeta` | `AccountUpn`, `ErrorCode` (int), `IPAddress`, `Country` |
| Entra ID Protection | Risk detections, risky sign-ins | Unfamiliar sign-in properties, anonymous IP, user-reported suspicious activity |
| Entra ID audit logs | `AuditLogs` | MFA method changes, consents and app registrations after the approval |

**Pre-check:** confirm `SigninLogs` (interactive sign-ins) is streamed to the SIEM with enough retention. `AuthenticationDetails` tells you *why* the MFA step failed (declined vs. no response vs. fraud reported); if that column is not ingested, you can still run the hunt but triage will be slower.

## 4. Hunt steps

1. **Run the query** for your platform. Step 1 mirrors the Sigma base rule (ResultType 500121) and groups denials **per user per one-hour bin**, like the Sigma correlation rule.
2. **Understand the correlation rule.** The Sigma file contains two rules: a low-severity base rule that matches every single denial, and an `event_count` correlation rule that fires when **one user collects five or more denials within one hour**. One denial is noise; five in an hour is a pattern. The KQL and SPL add the step the Sigma correlation cannot express: *was the burst followed by a success?*
3. **Read the join.** For each bin, the query looks for the first `ResultType 0` sign-in for the same user within one hour after the bin's **last** denial, and flags `SameIp`, `NonCorporateIp` and `NewCountry` for that success.
4. **Rank.** `RiskScore` adds burst, followed-by-success, same IP, new country, and non-corporate IP. A burst ending in an approval from the attacker's IP is the lead; isolated denials sink to the bottom but stay visible.
5. **Read the failure detail.** `DenialDetail` distinguishes *user declined* (someone saw the prompt and said no) from *did not respond* (phone lost, notifications off) and *reported as fraud*. Repeated declines at night from an unfamiliar IP is the push-bombing signature.
6. **Pivot from the success.** Take the approving sign-in's IP and session into `SigninLogs` (what else did it access), `AuditLogs` (MFA method registration, OAuth consent, inbox rules within the following hours — see HL-0011), and `OfficeActivity`.
7. **Call the user** through a known channel. Did they approve a prompt they did not initiate? Did anyone contact them claiming to be IT?
8. **Classify** each burst and record it in the hunt report.

Note: fixed one-hour bins can split a burst that spans the top of the hour into two smaller bins. If a user shows two adjacent bins just under the threshold, treat them as one burst.

## 5. Known benign sources (tune, don't ignore)

| Source | How to recognize |
|---|---|
| Accidental deny | One denial, corporate IP, the user's normal country, a normal sign-in later in the day |
| Lost or replaced phone | Several *did not respond* failures from the office IP, then a help desk MFA re-registration and a success from the same office IP |
| New device or app enrollment | Short burst during working hours from a known IP, tied to a device rollout or a ticket |
| Legacy client or misconfigured app retrying | Same app every time, regular cadence, often a service or shared account |

Scope exclusions to **user + IP range + time window** (for example, during a documented phone swap). Never exclude a user permanently from MFA-denial detection.

## 6. Triage questions

- How many denials, over how many minutes, and at what local time for the user?
- Were the prompts *declined*, *not answered*, or *reported as fraud*?
- Did a success follow? From the same IP as the denials? Is that IP corporate, a known VPN, or an anonymizer or hosting provider?
- Is the success country new for this user?
- What did the approved session do next: register a new MFA method, consent to an app, create inbox rules, download files?
- Does the user confirm initiating the sign-in?

## 7. Operationalize

- Promote the Sigma correlation rule (5 denials per user per hour) as an alert, and add the **burst followed by success** correlation from the KQL/SPL as a high-severity analytic.
- Enable **number matching** and **additional context** (application name and geographic location) in **Microsoft Authenticator** push notifications; number matching alone defeats blind approval. Move privileged users to phishing-resistant methods (FIDO2, Windows Hello for Business, certificate-based authentication).
- Use **Conditional Access** with **sign-in risk** (Entra ID Protection) to block or require re-authentication for medium/high risk sign-ins, and restrict where MFA can be completed (compliant devices, named locations).
- Turn on **Report suspicious activity** so users can flag prompts they did not initiate; a report marks the user as high risk and feeds the alert pipeline. Teach users: "If you did not just sign in, deny and report."
- On confirmation: revoke the user's sessions and refresh tokens, reset the password, review and remove newly registered MFA methods and OAuth grants (HL-0011).
- Record outcome, detections, and data gaps in `templates/hunt-report.md` and `templates/intel-feedback.md`.

## Lab notes

- The lab contains five days of Entra ID sign-in logs for about forty users, in both a flattened form (`data/lab/entra/signinlogs.jsonl`, `ResultType` as a number) and Sentinel schema (`data/lab/sentinel/SigninLogs.csv`, `ResultType` as a string, `AuthenticationDetails` as a JSON array).
- Routine noise includes morning sign-ins from the corporate egress IP and a handful of mistyped passwords (50126), which the query ignores.
- Expect several users with MFA denials. Only one of them clears the correlation threshold; at least one other comes close and will need a business explanation.
- Read the failure detail and the hour of day, not just the count.
- Note the exact time and IP of the approving sign-in, then take them into HL-0011.

## References

- MITRE ATT&CK T1621 — https://attack.mitre.org/techniques/T1621/
- MITRE ATT&CK T1078.004 — https://attack.mitre.org/techniques/T1078/004/
- Microsoft: How number matching works in MFA push notifications — https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-number-match
- CISA: More than a Password (MFA guidance, including number matching) — https://www.cisa.gov/MFA
- SigmaHQ rule repository — https://github.com/SigmaHQ/sigma
