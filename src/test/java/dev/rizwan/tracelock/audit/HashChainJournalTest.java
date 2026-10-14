package dev.rizwan.tracelock.audit;

import org.junit.jupiter.api.Test;
import java.lang.reflect.Method;
import static org.junit.jupiter.api.Assertions.*;

class HashChainJournalTest {
    @Test void verifiesValidChainAndSequentialLinks() {
        HashChainJournal journal = new HashChainJournal();
        var one = journal.append("case opened"); var two = journal.append("finding recorded");
        assertTrue(journal.verify()); assertEquals(one.hash(), two.previousHash());
        assertEquals(1, one.sequence()); assertEquals(2, two.sequence());
    }
    @Test void detectsPayloadTampering() throws Exception {
        HashChainJournal journal = new HashChainJournal(); journal.append("original payload");
        Method method = HashChainJournal.class.getDeclaredMethod("replacePayloadForTest", int.class, String.class);
        method.setAccessible(true); method.invoke(journal, 0, "changed payload");
        assertFalse(journal.verify());
    }
}
