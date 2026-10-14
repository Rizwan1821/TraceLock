package dev.rizwan.tracelock.detect;

import dev.rizwan.tracelock.model.Finding;
import dev.rizwan.tracelock.model.SecurityEvent;
import java.util.List;

public interface DetectionRule {
    String id();
    List<Finding> evaluate(List<SecurityEvent> events);
}
