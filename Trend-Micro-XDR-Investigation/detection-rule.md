# Custom detection model — Office Spawns CMD

**Purpose:** Detect Microsoft Word (`WINWORD.EXE`) creating a Windows command interpreter (`cmd.exe`) process on the lab endpoint `WIN10-CLIENT`.

- **Filter name:** `Office Spawns CMD`
- **Event type:** `ENDPOINT_ACTIVITY`
- **Event ID:** `TELEMETRY_PROCESS`
- **Event Sub ID:** `2` (Process Create)

```text
eventSubId:2 AND endpointHostName:"WIN10-CLIENT" AND processName:"*WINWORD.EXE" AND objectFilePath:"*cmd.exe"
```

**Model name:** `Suspicious Office CMD Execution`  
**Severity:** Low  
**Filter mode:** Single filter  
**Threshold:** 1  
**Group by:** Endpoint  
**Schedule:** Every 15 minutes; evaluate the last 15 minutes  
**Status during test:** Enabled

**Validated observation:** Four Word-spawned `cmd.exe` events on 11 October 2026 around 21:57:49–21:57:50 (local time). A Workbench alert was created around 22:13:13 with score 20. The alert was investigated and the associated SOC case was closed as Benign True Positive — Pen Test Result.

**Limitations:** This is a narrowly scoped demonstration. The query is specific to one endpoint, and legitimate Office-to-CMD automation may produce similar events. Further tuning, false-positive evaluation, generalization, contextual correlation, and a separate response-validation exercise would be needed for production deployment.
