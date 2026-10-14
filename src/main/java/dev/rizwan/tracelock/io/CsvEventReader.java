package dev.rizwan.tracelock.io;

import dev.rizwan.tracelock.model.SecurityEvent;
import dev.rizwan.tracelock.model.SecurityEvent.EventType;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/** Dependency-free reader for TraceLock's documented seven-column CSV format. */
public final class CsvEventReader {
    private static final String HEADER = "timestamp,event_id,username,source_ip,type,success,detail";
    private CsvEventReader() { }

    public static List<SecurityEvent> read(Path path) throws IOException {
        List<String> lines = Files.readAllLines(path);
        if (lines.isEmpty()) throw new IllegalArgumentException("CSV is empty");
        if (!lines.get(0).strip().equals(HEADER)) throw new IllegalArgumentException("Unexpected CSV header");
        List<SecurityEvent> events = new ArrayList<>();
        for (int lineNo = 2; lineNo <= lines.size(); lineNo++) {
            String line = lines.get(lineNo-1);
            if (line.isBlank() || line.stripLeading().startsWith("#")) continue;
            String[] c = line.split(",", -1);
            if (c.length != 7) throw new IllegalArgumentException("Expected 7 comma-separated columns at line " + lineNo);
            try {
                events.add(new SecurityEvent(Instant.parse(c[0].strip()), c[1].strip(), c[2].strip(),
                        c[3].strip(), EventType.valueOf(c[4].strip().toUpperCase()),
                        parseBoolean(c[5].strip()), c[6].strip()));
            } catch (RuntimeException ex) {
                throw new IllegalArgumentException("Invalid event at line " + lineNo + ": " + ex.getMessage(), ex);
            }
        }
        return List.copyOf(events);
    }
    private static boolean parseBoolean(String text) {
        if (text.equalsIgnoreCase("true")) return true;
        if (text.equalsIgnoreCase("false")) return false;
        throw new IllegalArgumentException("success must be true or false");
    }
}
