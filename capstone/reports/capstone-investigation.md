# CAPSTONE-001 — SOC Incident Investigation

## Executive Summary

Simulated telemetry from web-01 shows three failed SSH
authentication attempts against admin, followed by a
successful deploy login from the same source IP.

Shortly afterward, a deploy-owned bash process launched
curl, and network telemetry recorded an HTTP request for
/diag.sh.

The activity is suspicious and warrants investigation,
but the available evidence does not prove account compromise,
malicious script execution, persistence, or data exfiltration.

## Scope

- Host: web-01
- Suspicious authentication source: 198.51.100.24
- Script-request destination: 203.0.113.77:80
- Script path: /diag.sh
- Environment: Fully simulated incident

## Evidence Assessment

### Supported Observations

- Three failed SSH logins from one source.
- Successful deploy login from the same source.
- Bash spawned curl under deploy.
- HTTP GET for /diag.sh returned status 200.
- HTTP response size was recorded as 512 bytes.

### Not Established

- Whether the deploy login was unauthorized.
- Whether the HTTP response contained malicious code.
- Whether the downloaded content was saved or executed.
- Whether the unrelated HTTPS connection was malicious.
- Whether any persistence or data exfiltration occurred.

## Recommended Response

1. Validate whether the deploy login was authorized.
2. Preserve authentication, process, and network logs.
3. Review SSH session activity and parent process PID 4000.
4. Retrieve and safely inspect the HTTP response if available.
5. Investigate the HTTPS connection separately.
6. Consider credential revocation and host isolation only
   after confirming the appropriate operational context.

## Initial Classification

**Potential security incident — investigation required.**

**Confidence:** Moderate that the sequence is suspicious;
insufficient evidence to confirm compromise.

**Current status:** Under Investigation.

## Simulation Note

All addresses use documentation-only ranges. No real
attack traffic or compromise occurred.

## Final SOC Response Decision

**Case ID:** CAPSTONE-001

**Severity:** High — provisional.

**Classification:** Suspected account compromise.

**Confidence:** Moderate.

**Escalation:** Escalate to incident response for validation.

**Containment:** No actual host isolation or account disabling
was performed. This is a simulated incident.

**Required investigative actions:**

1. Confirm whether the deploy login was authorized.
2. Identify the SSH session associated with the deploy account.
3. Review the parent process (PID 4000) and related process tree.
4. Obtain and safely analyze the /diag.sh response content.
5. Determine whether the script was saved or executed.
6. Investigate the separate HTTPS connection without assuming
   that it represents exfiltration.
7. Preserve logs and determine whether additional hosts
   show related indicators.

## Final Evidence-Based Conclusions

- Repeated SSH authentication failures: Confirmed.
- Successful deploy login from the same source: Confirmed.
- Subsequent bash-to-curl process activity: Confirmed.
- HTTP GET for /diag.sh: Confirmed.
- Unauthorized account access: Not established.
- Malicious script execution: Not established.
- Persistence: Not established.
- Data exfiltration: Not established.

## Case Closure

**Exercise status:** Complete.

**Operational incident status:** Escalation recommended;
the suspected compromise remains unconfirmed.

**Disposition:** Suspicious activity requiring further
investigation, within an authorized simulation.

The simulated exercise is closed, but the evidence does
not support declaring a real incident fully resolved.
