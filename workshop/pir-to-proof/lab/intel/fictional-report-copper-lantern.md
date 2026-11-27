# FICTIONAL TRAINING REPORT: COPPER LANTERN Targets Aerospace Supplier Identity and Remote Access

> This report is fictional and was written for the CTI Hunt Loop Kit workshop. COPPER LANTERN is not a real threat actor, and all indicators are documentation-range addresses or invented names. TLP:CLEAR.

**Publisher:** Meridian Threat Research (fictional)
**Date:** 2027-02-24
**Publisher's confidence:** Moderate

## Key judgments

1. COPPER LANTERN is likely conducting a campaign against small and mid-sized aerospace suppliers to collect engineering and pricing data, probably to support a state-aligned procurement interest.
2. The group's main initial access path is **consent phishing**: lures that lead users to grant OAuth consent to look-alike productivity apps from unverified publishers. The apps request mail and file read scopes plus `offline_access`, which gives the group durable access without a password.
3. After initial access, the group has been observed **adding new credentials to existing, trusted service principals** to keep access if the malicious app is removed.
4. In two of the incidents behind this report, the group also used **stolen vendor credentials** to reach engineering networks through vendor remote access paths. We could not determine how those credentials were obtained.

## Observed behavior

| Behavior | ATT&CK (v20.0) | Notes |
| --- | --- | --- |
| User consent to malicious OAuth app | T1528 Steal Application Access Token | Apps named to resemble sync or document tools |
| Credentials added to existing service principal | T1098.001 Additional Cloud Credentials | Typically within 10 days of consent; often on weekends |
| Vendor remote access with valid credentials | ICS T0822 External Remote Services | Sessions at unusual hours from the vendor's normal country |

## Timing

Activity clusters between 22:00 and 04:00 UTC and on weekends, outside typical change windows.

## Indicators (fictional)

| Type | Value | Context |
| --- | --- | --- |
| App display name | MailSync Pro | Unverified publisher; requests Mail.Read, offline_access |
| App display name | DocView Connect | Unverified publisher; requests Mail.Read, Files.Read.All |
| IP address | 203.0.113.45 | Consent and later credential activity |
| IP address | 198.51.100.23 | Consent activity |

Indicators of this kind change quickly. The behaviors above are the more durable hunting target.

## Source note

Based on incident response engagements at four organizations and reporting shared through a sector sharing community. Two of the four organizations shared full logs.
