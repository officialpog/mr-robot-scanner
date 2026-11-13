# ReconScope development roadmap

## Delivered: passive assessment and saved reports

- Register/login, run a passive scan, inspect data and findings, reopen an owned
  report from server history, and export JSON.
- Evidence, confidence, impact, suggested fixes, stable rule IDs, and report
  policy version. Informational detections do not increase the risk score.
- Persisted per-check outcomes, scan timestamps, and partial/failed collection
  status. Existing accounts and databases remain compatible.

## Next: reliable execution and deployment controls

1. Install dependencies on a supported runtime, run the API tests and browser
   flow, then audit/update dependency pins. Validate with owned test fixtures.
2. Move scan execution into durable workers with persisted jobs, bounded
   concurrency, per-check and overall deadlines, cancellation, and recovery after
   restart. Add polling/progress to the UI. Do not call in-process background
   tasks a durable queue.
3. Define target scope per assessment. Enforce public-service destination rules
   at connection time and with egress controls; handle redirects and DNS rebinding.
   Private-network assessment should be a separate trusted deployment mode.
4. Enforce login/registration/scan limits with a shared limiter for multi-worker
   deployment. Add a database migration workflow and readiness checks.
5. Fetch each web resource once with bounded bytes/redirects; share its response
   across checks and preserve the inspected URL and collection time as evidence.

## Then: deeper assessment

- Parse and validate policy values, not just header presence. Record scope and
  limitations for each rule.
- Add controlled service discovery and approved Nmap/Nuclei integrations in
  isolated workers. Use explicit arguments, tool versions, execution deadlines,
  output limits, and curated non-destructive checks. Never execute user-supplied
  shell command text.
- Match verified versions against maintained vendor/advisory data, preserve the
  advisory source and retrieval time, and distinguish suspected from verified
  applicability. Do not infer an affected version from a product name alone.
- Add owner-authorized authenticated checks for weaknesses external probes
  cannot observe. Protect and avoid logging credentials.

## Then: remediation and retesting

- Group stable rule/asset findings across scans, record accepted risk and fix
  state, and compare repeat assessments. Distinguish "resolved" from "not assessed"
  when a later check fails or scope changes.
- Add asset inventories, scheduling, report retention, account recovery, and
  team roles as user needs become clear.

The present version is a passive assessor. It does not yet perform full-system
vulnerability coverage, verified exploit checks, or durable background execution.
