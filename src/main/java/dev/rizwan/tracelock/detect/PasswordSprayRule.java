package dev.rizwan.tracelock.detect;

import dev.rizwan.tracelock.model.Finding;
import dev.rizwan.tracelock.model.SecurityEvent;
import dev.rizwan.tracelock.model.SecurityEvent.EventType;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/** Flags one source IP failing against multiple distinct accounts inside a time window. */
public final class PasswordSprayRule implements DetectionRule {
    private final int minimumDistinctUsers;
    private final Duration window;

    public PasswordSprayRule(int minimumDistinctUsers, Duration window) {
        if (minimumDistinctUsers < 2) throw new IllegalArgumentException("minimumDistinctUsers must be >= 2");
        if (window == null || window.isZero() || window.isNegative()) throw new IllegalArgumentException("window must be positive");
        this.minimumDistinctUsers = minimumDistinctUsers;
        this.window = window;
    }
    @Override public String id() { return "TL-AUTH-001"; }

    @Override public List<Finding> evaluate(List<SecurityEvent> events) {
        List<SecurityEvent> failures = events.stream()
                .filter(e -> e.type() == EventType.LOGIN && !e.success())
                .sorted(Comparator.comparing(SecurityEvent::timestamp)).toList();
        Map<String, List<SecurityEvent>> byIp = failures.stream()
                .collect(Collectors.groupingBy(SecurityEvent::sourceIp, TreeMap::new, Collectors.toList()));
        List<Finding> findings = new ArrayList<>();
        for (var entry : byIp.entrySet()) {
            List<SecurityEvent> ipEvents = entry.getValue();
            for (SecurityEvent first : ipEvents) {
                Instant from = first.timestamp(), to = from.plus(window);
                List<SecurityEvent> slice = ipEvents.stream()
                        .filter(e -> !e.timestamp().isBefore(from) && !e.timestamp().isAfter(to)).toList();
                Set<String> users = slice.stream().map(SecurityEvent::username).collect(Collectors.toCollection(TreeSet::new));
                if (users.size() >= minimumDistinctUsers) {
                    findings.add(new Finding(id(), Finding.Severity.HIGH, "Possible password-spray pattern",
                            "One source IP recorded failed logins against " + users.size()
                                    + " distinct accounts within " + window.toMinutes()
                                    + " minutes (" + String.join(", ", users)
                                    + "). Validate against expected NAT/VPN traffic.",
                            "multiple", entry.getKey(), from, slice.get(slice.size()-1).timestamp(),
                            slice.stream().map(SecurityEvent::eventId).distinct().toList()));
                    break;
                }
            }
        }
        return List.copyOf(findings);
    }
}
