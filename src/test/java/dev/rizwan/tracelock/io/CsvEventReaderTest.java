package dev.rizwan.tracelock.io;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import static org.junit.jupiter.api.Assertions.*;

class CsvEventReaderTest {
    @TempDir Path dir;
    @Test void parsesDocumentedCsv() throws Exception {
        Path file = dir.resolve("events.csv");
        Files.writeString(file, "timestamp,event_id,username,source_ip,type,success,detail\n"
                + "2026-01-01T00:00:00Z,e1,alice,203.0.113.9,LOGIN,false,bad password\n");
        var result = CsvEventReader.read(file);
        assertEquals(1, result.size()); assertEquals("alice", result.get(0).username());
        assertFalse(result.get(0).success());
    }
    @Test void rejectsUnknownHeader() throws Exception {
        Path file = dir.resolve("events.csv"); Files.writeString(file, "a,b,c\n1,2,3\n");
        assertThrows(IllegalArgumentException.class, () -> CsvEventReader.read(file));
    }
}
