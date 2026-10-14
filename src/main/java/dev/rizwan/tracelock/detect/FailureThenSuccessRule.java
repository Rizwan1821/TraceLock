package dev.rizwan.tracelock.detect;

import dev.rizwan.tracelock.model.Finding;
import dev.rizwan.tracelock.model.SecurityEvent;
import dev.rizwan.tracelock.model.SecurityEvent.EventType;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

public final class FailureThenSuccessRule implements DetectionRule {
    private final int minimumFailures;
    private final Duration window;

    public FailureThenSuccessRule(int minimumFailures, Duration window) {
        if (minimumFailures < 1) throw new IllegalArgumentException("minimumFailures must be >= 1");
        if (window == null || window.isNegative() || window.isZero()) throw new IllegalArgumentException("window must be positive");
        this.minimumFailures = minimumFailures; this.window = window;
    }
    @Override public String id() { return "TL-AUTH-002"; }

    @Override public List<Finding> evaluate(List<SecurityEvent> events) {
        Map<String, List<SecurityEvent>> byUser = new TreeMap<>();
        events.stream().filter(e -> e.type() == EventType.LOGIN)
                .forEach(e -> byUser.computeIfAbsent(e.username(), ignored -> new ArrayList<>()).add(e));
        List<Finding> findings = new ArrayList<>();
        byUser.forEach((user, timeline) -> {
            timeline.sort(Comparator.comparing(SecurityEvent::timestamp));
            for (int i = 0; i < timeline.size(); i++) {
                SecurityEvent success = timeline.get(i);
                if (!success.success()) continue;
                Instant lower = success.timestamp().minus(window);
                List<SecurityEvent> failures = timeline.subList(0, i).stream()
                        .filter(e -> !e.success() && !e.timestamp().isBefore(lower)
                                && !e.timestamp().isAfter(success.timestamp())).toList();
                if (failures.size() >= minimumFailures) {
                    List<String> ids = new ArrayList<>(failures.stream().map(SecurityEvent::eventId).toList());
                    ids.add(success.eventId());
                    findings.add(new Finding(id(), Finding.Severity.MEDIUM,
                            "Repeated failures followed by a successful login",
                            user + " had " + failures.size() + " failed login(s) followed by a success within "
                                    + window.toMinutes() + " minutes. Validate the session and MFA context.",
                            user, success.sourceIp(), failures.get(0).timestamp(), success.timestamp(), ids));
                    break;
                }
            }
        });
        return List.copyOf(findings);
    }
}
