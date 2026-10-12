# TrendAI Vision One — EDR/XDR Incident Investigation

**SOC L1 Lab | Custom Detection Engineering | Workbench Investigation | Case Closure**

> **Language:** The completed report is currently available in Turkish. An English edition will be added later.
>
> **Türkçe:** Türkçe olay inceleme raporu tamamlandı. İngilizce sürümü daha sonra eklenecek.

## Report / Rapor

📄 **[Türkçe Olay İnceleme Raporu (PDF)](./Incident_Report_TR.pdf)**

## Overview / Genel bakış

In this authorized VMware lab, I used TrendAI Vision One to investigate Microsoft Word initiating command-shell activity. A controlled Word macro executed four non-destructive discovery commands (`whoami`, `hostname`, `ipconfig /all`, and `tasklist`). Endpoint process and Office VBA-related AMSI telemetry were reviewed in XDR Data Explorer.

Built-in detection did not produce a Workbench alert for this specific test. I therefore created a **custom filter** and a **custom detection model** that identified Word spawning `cmd.exe`. Repeating the simulation generated a Workbench alert containing four matching events. I investigated the timeline, process execution profile and impact scope, created a SOC case, documented findings and closed it as **Benign True Positive — Pen Test Result** because the activity was an authorized security test.

**Important limitation:** The phishing-themed test email and the locally executed macro-enabled DOCM were **separate stages**. Gmail delivered a clean attachment and blocked the macro-enabled DOCM. This is **not** presented as an end-to-end malicious email compromise. The test did not validate endpoint isolation or comprehensive network/persistence hunting.

## Key facts / Temel bilgiler

| Item | Value |
| --- | --- |
| Platform | TrendAI Vision One EDR/XDR |
| Endpoint | `WIN10-CLIENT` (Windows 10 Pro, VMware) |
| Context | Authorized cybersecurity laboratory |
| Detection model | `Suspicious Office CMD Execution` |
| Custom filter | `Office Spawns CMD` |
| Detection rule | Word `WINWORD.EXE` spawning `cmd.exe` |
| Matching events | 4 |
| Alert score | 20 (custom model severity: Low) |
| Impact scope | 1 endpoint / 1 user |
| Workbench alert | `WB-69161-20261011-00000` |
| Case | `CL-10-03310-20261011-00001` |
| Final disposition | Benign True Positive — Pen Test Result |
| Case status | Closed, 12 October 2026 |

## Detection rule

```text
eventSubId:2 AND endpointHostName:"WIN10-CLIENT" AND processName:"*WINWORD.EXE" AND objectFilePath:"*cmd.exe"
```

This is a **lab-scoped demonstration rule**, not a production-ready detector. It would need tuning, validation and appropriate response playbooks before operational use.

## Investigation evidence

The PDF includes annotated evidence from the email/header review, VBA macro, XDR process telemetry, AMSI activity, custom rule/model configuration, Workbench alert and timeline, execution profile, impact scope, and case closure. The report retains the original event context while masking personal test email addresses.

## Scope & ethics

- Only an owned/authorized isolated test environment was used.
- The executed commands were discovery-only; no exfiltration, persistence or lateral movement was performed.
- The observed alert is a correct behavior match, **not** proof of a real attacker compromise.

---

**Author:** Kadirhan Güneyli  
**Project date:** 11–12 October 2026
