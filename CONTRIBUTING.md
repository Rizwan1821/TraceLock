# Contributing

1. Make a feature branch.
2. Keep detection behavior deterministic and explainable.
3. Add tests for normal, boundary, and malformed-input cases.
4. Never commit real telemetry, secrets, or personal data.
5. Run `mvn clean verify` before opening a pull request.

New rules should implement `DetectionRule`, use a unique rule ID, explain expected evidence and likely false positives, and include unit tests.
