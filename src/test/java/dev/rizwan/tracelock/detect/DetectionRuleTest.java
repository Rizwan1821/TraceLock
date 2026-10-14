package dev.rizwan.tracelock.detect;

import dev.rizwan.tracelock.model.SecurityEvent;
import dev.rizwan.tracelock.model.SecurityEvent.EventType;
import org.junit.jupiter.api.Test;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class DetectionRuleTest {
    private SecurityEvent event(String id, int minute, String user, String ip, boolean success) {
        return new SecurityEvent(Instant.parse("2026-01-01T00:00:00Z").plusSeconds(minute*60L),
                id, user, ip, EventType.LOGIN, success, "test");
    }
    @Test void detectsFailuresAcrossDistinctAccounts() {
        var events = List.of(event("e1",0,"alice","203.0.113.9",false),
                event("e2",1,"bob","203.0.113.9",false), event("e3",2,"carol","203.0.113.9",false),
                event("e4",3,"david","203.0.113.9",false));
        var findings = new PasswordSprayRule(4, Duration.ofMinutes(10)).evaluate(events);
        assertEquals(1, findings.size());
        assertEquals("TL-AUTH-001", findings.get(0).ruleId());
        assertEquals(4, findings.get(0).evidenceEventIds().size());
    }
    @Test void ignoresFailuresOutsideConfiguredWindow() {
        var events = List.of(event("e1",0,"alice","203.0.113.9",false),
                event("e2",20,"bob","203.0.113.9",false), event("e3",40,"carol","203.0.113.9",false),
                event("e4",60,"david","203.0.113.9",false));
        assertTrue(new PasswordSprayRule(4, Duration.ofMinutes(10)).evaluate(events).isEmpty());
    }
    @Test void detectsRepeatedFailuresFollowedBySuccess() {
        var events = List.of(event("e1",0,"alice","203.0.113.9",false),
                event("e2",1,"alice","203.0.113.9",false), event("e3",2,"alice","203.0.113.9",false),
                event("e4",3,"alice","203.0.113.9",true));
        var findings = new FailureThenSuccessRule(3, Duration.ofMinutes(15)).evaluate(events);
        assertEquals(1, findings.size());
        assertEquals("TL-AUTH-002", findings.get(0).ruleId());
        assertTrue(findings.get(0).explanation().contains("3 failed login"));
    }
}
