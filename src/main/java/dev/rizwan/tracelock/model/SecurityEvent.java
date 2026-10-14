package dev.rizwan.tracelock.model;

import java.time.Instant;
import java.util.Objects;

/** Immutable normalized event; adapters can later ingest logs from different sources. */
public record SecurityEvent(Instant timestamp, String eventId, String username,
                            String sourceIp, EventType type, boolean success, String detail) {
    public SecurityEvent {
        Objects.requireNonNull(timestamp, "timestamp");
        eventId = required(eventId, "eventId");
        username = required(username, "username");
        sourceIp = required(sourceIp, "sourceIp");
        Objects.requireNonNull(type, "type");
        detail = detail == null ? "" : detail.strip();
    }
    private static String required(String value, String field) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(field + " must not be blank");
        return value.strip();
    }
    public enum EventType { LOGIN, PASSWORD_RESET, MFA_CHALLENGE, PRIVILEGE_CHANGE, ACCOUNT_LOCKED }
}
