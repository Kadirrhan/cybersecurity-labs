# Investigation Evidence / İnceleme Kanıtları

These screenshots document the authorized TrendAI Vision One EDR/XDR lab. They are **selected investigation exhibits**, not a continuous malicious email-to-compromise trace. The macro-enabled DOCM was executed locally, separately from the Gmail delivery test.

| File | What it documents | Report section |
| --- | --- | --- |
| `01-phishing-email.png` | Test invoice message and clean Gmail attachment (not the executed DOCM) | 4.1 |
| `02-email-header-auth.png` | Sender mismatch and SPF/DKIM/DMARC PASS evidence | 4.1 |
| `03-vba-autoopen-macro.png` | The `AutoOpen()` VBA code launching benign system discovery commands | 4.2 |
| `04-office-process-creation.png` | Word-related process creation telemetry, including command line | 5.1–5.2 |
| `05-amsi-telemetry.png` | Office VBA-related AMSI event (visibility, not proof of prevention) | 5.3 |
| `06-workbench-alert.png` | Workbench detection score 20, model severity Low, one endpoint/user | 7.1 |
| `07-workbench-timeline.png` | Four custom-filter events in the incident timeline | 7.2 |
| `08-execution-profile.png` | Office → CMD process relationship and linked output artifact | 7.4 |
| `09-impact-scope.png` | One endpoint and one user in observed alert scope | 7.3 |
| `10-case-closure.png` | Closed SOC case, Benign True Positive / Pen Test Result | 10 |

**Privacy:** Personal test email addresses were redacted from the two Gmail exhibits before public sharing. The report PDF contains evidence too. Do not upload raw screenshots with unmasked personal email addresses to public repositories.

**Accuracy:** A successful detection does not imply automatic blocking. No malicious compromise was established from the reviewed evidence, and full network/persistence hunting was outside the tested scope.
