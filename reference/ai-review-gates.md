# AI Review Gates

LLM assistants help most where work is slow and text-heavy, and carry the most risk where a model could state a conclusion the data does not support.

| Stage | Useful AI assistance | Review gate |
| --- | --- | --- |
| Requirement | Summarizing threat reporting against existing PIRs | Humans write and approve PIRs |
| Hypothesis | Extracting behaviors and ATT&CK candidates from a report | Analyst verifies every technique ID against the source text |
| Collection and hunt | Drafting KQL, SPL, or Sigma from the card | Queries reviewed and tested on known-good data before use |
| Outcome | Summarizing the hunt log for the record | No model output closes a hunt or declares a negative |
| Feedback | Clustering outcomes by source and technique | Source scores set by the CTI lead |

## Treat the AI pipeline as an attack surface

- Treat every report, feed item, and web page passed to a model as untrusted input.
- Log what the model was given and what it returned.
- Hunt your own pipeline: ATT&CK v20.0 includes Indirect Prompt Injection (T1698), Direct Prompt Injection (T1699), and AI Result Poisoning (T1608.007).
- See the OWASP AI Exchange (https://owaspai.org) for threats and controls.
