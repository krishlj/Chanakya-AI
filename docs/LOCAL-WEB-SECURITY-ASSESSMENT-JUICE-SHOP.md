# Local Web Security Assessment & Remediation with Chanakya AI

## Overview

This case study demonstrates the first local-web security workflow
performed with **Chanakya AI** against an OWASP Juice Shop training
instance running on the local machine.

The workflow was intentionally limited to:

1.  Discover a local web service.
2.  Perform a benign, read-only HTTP request.
3.  Inspect the response for security-relevant observations.
4.  Identify a wildcard CORS configuration.
5.  Manually remediate the application source to restrict CORS.
6.  Document the remediation and verification status.

> **Authorization:** The Juice Shop instance used in this exercise is a
> local training application owned/controlled by the operator.

> **Important scope note:** Chanakya AI v1.1.0 is a read-only
> investigation tool. It does **not** perform source-code modification
> or remediation itself. In this exercise, Chanakya performed the
> discovery and evidence collection; the CORS remediation was performed
> manually in the Juice Shop source code.

## Environment

  Component               Details
  ----------------------- ------------------------------------------
  Security agent          Chanakya AI v1.1.0
  Target                  Local OWASP Juice Shop training instance
  Target address          `127.0.0.1:3000`
  Container               `juice-shop`
  Docker image            `bkimminich/juice-shop`
  Application version     20.2.0
  Investigation workdir   `D:\Chanakya-Data`
  Probe type              Read-only HTTP GET
  Endpoint tested         `/rest/products/search?q=apple`

The investigation data was kept outside the Chanakya AI Git repository.

## 1. Discovery with Chanakya AI

The first objective was to confirm that the local Juice Shop web service
responded normally.

``` powershell
python -m chanakya.cli "On this machine I run a local OWASP Juice Shop training instance that I own, on loopback port 3000. Perform ONE read-only HTTP GET to confirm that the local web application responds normally. Use http_probe_local once against the local-host target on port 3000 with path /. No injection, exploitation, modification, or destructive actions. After the probe, conclude the investigation." --workdir D:\Chanakya-Data --require-approval --max-turns 3
```

Investigation ID:

``` text
cb4da3c7-6ff4-4b73-8740-170a5855503b
```

Result:

-   HTTP GET completed successfully.
-   HTTP response: **200 OK**
-   Juice Shop was confirmed reachable on `127.0.0.1:3000`.
-   Response headers were collected as evidence.
-   Chanakya recorded security-relevant observations without modifying
    the application.

## 2. Benign Application Discovery

The next objective was to inspect the local product-search endpoint
using a normal search value.

``` powershell
python -m chanakya.cli "On this machine I run a local OWASP Juice Shop training instance that I own, on loopback port 3000. Perform ONE read-only HTTP GET to the product search endpoint using the benign query "apple". Use http_probe_local once against the local-host target on port 3000 with path /rest/products/search?q=apple. Do not inject payloads, exploit anything, modify the application, or perform destructive actions. After the probe, conclude the investigation." --workdir D:\Chanakya-Data --require-approval
```

Investigation ID:

``` text
e463d909-3126-453d-a5ae-683ff31f5265
```

The investigation completed with:

-   **1 evidence record**
-   **3 findings**
-   **2 informational risk assessments**
-   **0 review anomalies**

The evidence showed:

``` text
HTTP/1.1 200 OK
Content-Type: application/json
```

The benign search returned three matching products:

-   Apple Juice
-   Apple Pomace
-   Pineapple Juice

## 3. Security-Relevant Observation: Wildcard CORS

Among the response headers, Chanakya observed:

``` text
Access-Control-Allow-Origin: *
```

This was recorded as a security-relevant configuration observation.

### What this means

A wildcard CORS policy indicates that the application is configured to
allow cross-origin browser requests broadly.

The finding should be described precisely as:

> **Wildcard CORS configuration identified**

It should **not** automatically be described as a confirmed exploitable
CORS vulnerability based only on this observation.

Actual exploitability depends on the application's authentication model,
response data, credential behavior, browser enforcement, and other
application-specific conditions.

For this training exercise, the wildcard configuration was selected as
the remediation target.

## 4. Independent Confirmation Before Remediation

The response was independently checked from PowerShell:

``` powershell
curl.exe -i "http://127.0.0.1:3000/rest/products/search?q=apple"
```

The response again contained:

``` text
Access-Control-Allow-Origin: *
```

This provided additional confirmation of the **BEFORE** state.

The original Juice Shop container remained running on port 3000 and was
not modified during the investigation.

## 5. Manual Remediation

The Juice Shop source was cloned separately for remediation.

The original CORS configuration was:

``` ts
/* Bludgeon solution for possible CORS problems: Allow everything! */
app.options('*', cors())
app.use(cors())
```

This was changed to an explicit origin allowlist:

``` ts
/* Remediation: restrict CORS to the local Juice Shop origin */

const allowedOrigins = new Set([
  'http://127.0.0.1:3000',
  'http://localhost:3000'
])

const corsOptions = {
  origin: (origin: string | undefined, callback: (error: Error | null, allow?: boolean) => void) => {
    if (!origin || allowedOrigins.has(origin)) {
      callback(null, true)
    } else {
      callback(new Error('Origin not allowed by CORS'))
    }
  }
}

app.options('*', cors(corsOptions))
app.use(cors(corsOptions))
```

### Intended remediation behavior

  Origin                    Intended result
  ------------------------- -----------------
  No Origin header          Allowed
  `http://127.0.0.1:3000`   Allowed
  `http://localhost:3000`   Allowed
  `http://evil.example`     Rejected

The policy changed from **allow all origins** to **allow only explicitly
configured local origins**.

## 6. Attempted Remediated Container Build

A separate Docker image was intended for the AFTER-state verification so
the original port-3000 container could remain untouched.

``` powershell
docker build -t juice-shop-remediated:20.2.0 .
```

The build progressed through the application/frontend build but failed
during the SBOM-related build step because the expected frontend
metafile was missing:

``` text
Error: Missing metafile: dist/frontend/stats.json
```

Therefore:

-   `juice-shop-remediated:20.2.0` was **not created**.
-   No remediated container was running on port 3001.
-   The original Juice Shop on port 3000 remained untouched.

A later attempt to use the modified source directly was also blocked
because Node.js/npm was not installed on the Windows host:

``` text
npm : The term 'npm' is not recognized...
```

## 7. AFTER-State Verification Status

The intended verification was to start the remediated application on
port 3001 and repeat the same benign request.

However, port 3001 was not listening.

Direct verification showed:

``` powershell
curl.exe -i -H "Origin: http://evil.example" "http://127.0.0.1:3001/rest/products/search?q=apple"
```

Result:

``` text
curl: (7) Failed to connect to 127.0.0.1:3001
```

Chanakya was also asked to verify the remediated service. That
investigation failed because the HTTP probe could not connect to the
target service.

Investigation ID:

``` text
05a42b1a-f8d8-49da-9f4a-e654246077d8
```

The investigation recorded:

-   2 HTTP probe requests
-   both approved
-   both failed at tool execution
-   0 evidence records
-   0 findings
-   0 risk assessments

The review showed a consistent audit record, but there was no successful
AFTER-state HTTP evidence.

### Verification conclusion

The remediation was **implemented in source code**, but the
rebuilt/running Docker application was not successfully produced and
verified.

This case study intentionally does **not** claim that the running
container's CORS behavior was successfully verified after remediation.

## 8. What Chanakya AI Demonstrated

``` text
Local Web Application
        |
        v
Chanakya AI
        |
        v
Local HTTP Discovery
        |
        v
Benign Endpoint Probe
        |
        v
Evidence Collection
        |
        v
Security-Relevant Finding
        |
        v
Manual Source Remediation
        |
        v
Attempted Rebuild
        |
        v
AFTER Verification
        |
        +---- Verification deferred because remediated service
              was not successfully built/running
```

Chanakya provided the **controlled discovery and evidence layer**.

The source-code remediation remained an **operator-controlled
activity**, consistent with the v1.1.0 architecture.

## 9. Security Controls Demonstrated

### Read-only capability

The HTTP investigation used:

``` text
http_probe_local
```

It performs a bounded HTTP GET against the local host.

### Localhost confinement

The capability targets:

``` text
127.0.0.1
```

### Human approval

The investigations were executed with:

``` text
--require-approval
```

The HTTP probe therefore required explicit operator approval.

### Evidence grounding

The CORS observation came from the actual HTTP response collected by
Chanakya rather than from an unsupported model assumption.

### Risk separation

Chanakya's risk assessment is generated by deterministic rules. The
model's finding and the rule-based risk assessment are separate stages.

### Durable auditability

The investigations produced durable audit records that could be reviewed
after execution.

## 10. Lessons Learned

### Discovery and remediation are separate responsibilities

Chanakya v1.1.0 can investigate a local web service but does not modify
application source code.

The operator performed the CORS remediation manually.

### A finding is not automatically an exploit

The presence of:

``` text
Access-Control-Allow-Origin: *
```

is evidence of a broad CORS configuration. It does not by itself prove
that sensitive authenticated data can be stolen cross-origin.

### Evidence must be separated from assumptions

The BEFORE state was supported by actual HTTP evidence.

The AFTER state was **not** successfully verified because the remediated
service was not running.

### Verification is part of the security workflow

A source-code change should ideally be followed by:

``` text
Build → Deploy → Repeat the same probe → Compare BEFORE vs AFTER
```

In this exercise, the final runtime verification was intentionally
deferred rather than treating an untested source change as proof of
remediation.

## 11. Portfolio Summary

### Objective

Use Chanakya AI to investigate a locally hosted web application and
identify a security-relevant configuration issue.

### Target

OWASP Juice Shop running locally on port 3000.

### Chanakya capability

``` text
http_probe_local
```

### Finding

Wildcard CORS configuration:

``` text
Access-Control-Allow-Origin: *
```

### Remediation

Replaced unrestricted CORS with an explicit local-origin allowlist.

### Verification

BEFORE state confirmed.

AFTER source change completed.

AFTER runtime verification deferred because the remediated Docker
image/container was not successfully built and started.

### Security model demonstrated

``` text
Discover
  ↓
Collect Evidence
  ↓
Identify Finding
  ↓
Manually Remediate
  ↓
Re-test
  ↓
Verify Evidence
```

This represents Chanakya AI's current role as an **AI-assisted,
controlled security investigation agent**, while keeping remediation
under explicit operator control.
