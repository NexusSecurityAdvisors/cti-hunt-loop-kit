# Tool Map by Loop Stage

Examples only, not endorsements. Listed alphabetically. Check current licensing before adopting.

| Stage | Open-source or free | Commercial examples |
| --- | --- | --- |
| 1. Requirement | CTI-CMM worksheets; spreadsheet PIR register | Requirements modules in threat intelligence platforms |
| 2. Hypothesis | ATT&CK Navigator, MISP, OpenCTI, PEAK templates | Commercial intelligence services and TIPs |
| 3. Collection and hunt | Malcolm (CISA/INL), Sigma, Suricata, Velociraptor, Wazuh, Zeek; Chainsaw and Hayabusa for Windows logs | EDR and SIEM platforms; OT network monitoring platforms |
| 4. Outcome | Sigma rules; DeTT&CT for coverage tracking; open-source case management | SOAR and case management modules |
| 5. Feedback | OpenCTI dashboards, Jupyter notebooks, spreadsheet scoring | TIP analytics and source-scoring features |
| Validation | Atomic Red Team, MITRE Caldera | Breach and attack simulation platforms |

## Minimum free stack for a two-person team

- PIR register, hypothesis cards, and logs in a shared spreadsheet or wiki
- MISP or OpenCTI for intelligence storage and ATT&CK tagging
- Velociraptor for endpoint hunting; Zeek or Malcolm for network and OT visibility
- Sigma for writing detections once and converting them to the SIEM in place
- ATT&CK Navigator layers to show coverage gained each quarter
