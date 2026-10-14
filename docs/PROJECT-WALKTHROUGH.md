# TraceLock: Project Walkthrough

## Problem
Authentication logs are noisy. Analysts need a repeatable way to group related failures, understand why a finding appeared, and preserve an auditable record of triage.

## Workflow
A local CSV export is parsed into `SecurityEvent` records. Multiple `DetectionRule` implementations evaluate it. Each `Finding` contains evidence IDs, source, timestamps, severity, and an explanation. A hash-chain journal then records the analysis summary.

## Main classes
- `SecurityEvent`: immutable event data model.
- `DetectionRule`: interface for independently testable rules.
- `PasswordSprayRule`: correlates failed logins across accounts by source IP.
- `FailureThenSuccessRule`: correlates repeated failed attempts and a later success for the same account.
- `Finding`: analyst-facing result with evidence.
- `HashChainJournal`: verifies ordered entries linked with SHA-256.
- `CsvEventReader`: validates the input shape.
- `TraceLock`: application entry point and report renderer.

## Engineering choices
1. Java records keep data models concise and immutable.
2. Detection thresholds are parameters, which makes boundary conditions testable.
3. Evidence IDs stay attached to findings to support validation.
4. The project does not contact remote systems; the exercise is safe to run locally.
5. Hash-chaining illustrates tamper evidence but does not replace protected evidence storage.

## Review questions
- Do events outside a rule's time window contribute to the finding?
- Is the successful authentication later than the required failures?
- Does altering a journal payload cause verification to fail?
- Does malformed CSV show a line number?
- Are detections presented as leads rather than proof of compromise?

## Next step
A production-style extension should add a maintained CSV parser, JSON output, persistent storage, explicit case IDs, externally anchored journal heads, a threat model, and controls for retention and access.
