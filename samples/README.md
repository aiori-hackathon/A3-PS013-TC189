# Synthetic incident scenarios

These datasets are synthetic and use documentation-only IP ranges
(`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and example hostnames.
They are intended for demos and automated ingestion checks.

Each scenario contains:

- `auth.log`
- `access.log`

## Scenario 1: SSH brute force and web probing

- SSH invalid-user and valid-account failures from `203.0.113.50`, followed by a
  successful login and sudo.
- Web requests from the same IP for `/admin`, `/wp-login.php`, `/.env`, and the
  login page.
- Expected: 7 Linux auth events, 5 web events, no parsing issues.

## Scenario 2: Web intrusion indicators

- SQL injection and path-traversal probes, `sqlmap` user agents, authenticated
  access, and a successful admin request.
- Authentication failures for `bob` from the same source IP followed by a
  successful login and sudo.
- Expected: 4 Linux auth events, 5 web events, no parsing issues.

## Scenario 3: timezone and year uncertainty

- RFC 3164 auth lines with no year.
- A web access line with a wall-clock timestamp and no UTC offset.
- Without metadata, these records are retained but flagged as `missing_year` or
  `missing_timezone`.
- With `timezone_hint=Asia/Kolkata` and `default_year=2026`, expected normalized
  times are:
  - `2026-10-31T18:10:01Z` auth failure
  - `2026-10-31T18:11:10Z` auth success
  - `2026-10-31T18:12:00Z` web request
- Expected: 2 Linux auth events, 1 web event.

## Loading a scenario

Start CyberTrace from `backend` (see the main README), then run from the project
root. The dashboard is the easiest option; the equivalent API calls are:

```powershell
$base = "http://127.0.0.1:8000/api"
$case = Invoke-RestMethod -Method Post -Uri "$base/investigations" `
  -ContentType "application/json" `
  -Body '{"name":"Scenario 1 - SSH brute force"}'
$id = $case.id

curl.exe -s -X POST "$base/investigations/$id/evidence" `
  -F "file=@samples/scenario_1_ssh_bruteforce/auth.log" `
  -F "source_type=linux_auth" `
  -F "source_name=bastion-auth" `
  -F "hostname=bastion"

curl.exe -s -X POST "$base/investigations/$id/evidence" `
  -F "file=@samples/scenario_1_ssh_bruteforce/access.log" `
  -F "source_type=web_access" `
  -F "source_name=portal-web" `
  -F "hostname=portal"

Invoke-RestMethod "$base/timeline?investigation_id=$id&limit=100"
```

For Scenario 3, add the explicit collection context to both uploads:

```powershell
-F "timezone_hint=Asia/Kolkata" -F "default_year=2026"
```

Without those values the upload still succeeds and the original evidence is
preserved, but affected events have `timestamp_utc = null` and an uncertainty
status. This is intentional: CyberTrace does not invent a timezone or year.
