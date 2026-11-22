# Example Detections

Two Sigma rules produced in the workshop lab from Hypothesis A. They are starting points, not production content.

- Field names follow common Entra ID audit log mappings and differ between pipelines. Map them before converting.
- Test on known-good data first, then on the lab's planted events.
- The change-window and ticket conditions from the lab are correlations; implement them in your SIEM with your change calendar.

Both rules parse and convert with pySigma (checked with the Splunk backend). With network access, `sigma check detections/sigma/` from [sigma-cli](https://github.com/SigmaHQ/sigma-cli) also validates tags.
