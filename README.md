# TraceLock 🔎
### Explainable authentication-event triage & tamper-evident incident journaling

TraceLock is a Java 17 command-line investigation tool that reads normalized authentication events, applies transparent detection rules, shows evidence behind each alert, and records analysis events in a SHA-256 hash-chain journal.

It is a blue-team portfolio project: no live-system access, no exploit code, and no opaque “AI says suspicious” result. Every finding carries a rule ID, time window, source, and evidence event IDs.

> **Lab tool, not a production SIEM.** Rule hits are heuristics that need analyst validation. The journal is an in-memory tamper-evidence demonstration, not durable evidence storage or a digital signature.

## What makes it different

- **Explainable detections:** rule IDs (`TL-AUTH-001`, `TL-AUTH-002`) and matching evidence event IDs accompany alerts.
- **Cross-account correlation:** identifies a source IP failing against multiple distinct accounts inside ten minutes.
- **Account timeline reasoning:** detects repeated failures followed by a successful login within a configured time window.
- **Tamper-evident journal:** entries link to the preceding SHA-256 hash; payload edits break validation.
- **Tested Java design:** immutable records, a rule interface, Maven and JUnit tests.
- **CI-ready:** GitHub Actions compiles and tests on pushes and pull requests.

## Architecture

```text
CSV event log -> CsvEventReader -> SecurityEvent
                                  /           \
                         PasswordSprayRule  FailureThenSuccessRule
                                  \           /
                                   Findings
                                      |
                               HashChainJournal
                                      |
                              Analyst report
```

## Requirements and run

Install JDK 17+ and Maven 3.9+.

```bash
java -version
mvn -version
mvn clean verify
mvn package
java -jar target/tracelock-1.0.0.jar data/sample-events.csv
```

## Example report

```text
=== TraceLock Investigation Report ===
Events loaded : 10
Findings      : 2

1. [HIGH] Possible password-spray pattern
   Rule      : TL-AUTH-001
   Account   : multiple
   Source IP : 203.0.113.44
   Evidence  : evt-001, evt-002, evt-003, evt-004

2. [MEDIUM] Repeated failures followed by a successful login
   Rule      : TL-AUTH-002
   Account   : emma
   Source IP : 198.51.100.20
   Evidence  : evt-005, evt-006, evt-007, evt-008

Audit journal: 4 entries; hash-chain valid = true
```

## Input CSV

The sample parser expects exactly these seven columns. Values must not contain commas in this starter version.

```csv
timestamp,event_id,username,source_ip,type,success,detail
2026-06-15T09:00:00Z,evt-001,alice,203.0.113.44,LOGIN,false,invalid password
```

Event types: `LOGIN`, `PASSWORD_RESET`, `MFA_CHALLENGE`, `PRIVILEGE_CHANGE`, `ACCOUNT_LOCKED`. Timestamps must be ISO-8601 instants, e.g. `2026-06-15T09:00:00Z`.

## Detection rules

| Rule | Default condition | Severity | Analyst follow-up |
|---|---|---|---|
| `TL-AUTH-001` | At least four distinct accounts fail from one IP inside 10 minutes | High | Check VPN/NAT egress and legitimate automation |
| `TL-AUTH-002` | At least three failures then a success for one account inside 15 minutes | Medium | Validate session, user, device, and MFA context |

Both are heuristics. They can create false positives or miss attacks.

## Hash-chain limits

Each entry hashes `sequence + newline + previousHash + newline + payload`. The next entry links to the previous hash. The verifier detects changes against the existing linked values, but a process able to rewrite the whole chain can recalculate it. Production evidence needs protected persistence and external anchoring or signing.

## Testing

```bash
mvn test
```

The test suite covers cross-account bursts, window boundaries, failure-then-success correlation, hash-chain links/tampering, and CSV validation.

## Roadmap

1. Quote-aware CSV and JSONL input.
2. Configurable rule thresholds.
3. Persistent append-only journal and externally anchored head hash.
4. JSON/Markdown case report export.
5. Local dashboard with roles and audit trails.
6. Additional rules for MFA fatigue and privilege changes after login.

## Security and privacy

Use only datasets you own or are authorized to analyze. Never commit real usernames, tokens, or production logs. Sample IPs and events are synthetic. TraceLock does not scan networks, attack accounts, or connect to remote systems.

## Author

**Rizwan Abdul** · Java · Cybersecurity · Defensive Security Engineering  
GitHub: [@Rizwan1821](https://github.com/Rizwan1821)

## License

MIT. See [LICENSE](LICENSE).
