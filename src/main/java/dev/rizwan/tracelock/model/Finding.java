package dev.rizwan.tracelock.model;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

public record Finding(String ruleId, Severity severity, String title, String explanation,
                      String username, String sourceIp, Instant firstSeen, Instant lastSeen,
                      List<String> evidenceEventIds) {
    public Finding {
        Objects.requireNonNull(ruleId); Objects.requireNonNull(severity); Objects.requireNonNull(title);
        Objects.requireNonNull(explanation); Objects.requireNonNull(username); Objects.requireNonNull(sourceIp);
        Objects.requireNonNull(firstSeen); Objects.requireNonNull(lastSeen);
        evidenceEventIds = List.copyOf(evidenceEventIds);
    }
    public enum Severity { LOW, MEDIUM, HIGH, CRITICAL }
}
