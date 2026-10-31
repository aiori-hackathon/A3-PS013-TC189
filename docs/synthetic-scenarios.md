# Synthetic Scenarios

Synthetic scenarios are in `samples/`.

## Scenario 1: SSH brute force and web probing

- 7 Linux authentication events and 5 web events.
- Shared source IP between authentication failures and web requests.

## Scenario 2: Web intrusion indicators

- 4 Linux authentication events and 5 web events.
- SQL injection and path-traversal probes.

## Scenario 3: Timestamp uncertainty

- 2 Linux authentication events and 1 web event.
- Requires `timezone_hint=Asia/Kolkata` and `default_year=2026` for UTC normalization.

## Loading a scenario

See `samples/README.md` for API commands.

## Additional Phase 5 scenarios

- Scenario D: agent disconnection and recovery. Procedure: stop the agent, generate events, restart the agent, then inspect coverage gaps, buffered delivery, duplicate handling, and recovered events.
- Scenario E: timestamp uncertainty. Use Scenario 3 without metadata to confirm unknown timestamps are flagged.
- Scenario F: evidence integrity and parsing failure. Modify a stored evidence copy after hashing and verify a mismatch; include malformed and unsupported records.
