package dev.rizwan.tracelock.audit;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

/**
 * In-memory hash-chain demonstration. It is not durable storage or a digital
 * signature; production use needs persistence and external anchoring/signing.
 */
public final class HashChainJournal {
    private static final String GENESIS = "0".repeat(64);
    private final List<Entry> entries = new ArrayList<>();

    public synchronized Entry append(String payload) {
        if (payload == null || payload.isBlank()) throw new IllegalArgumentException("payload must not be blank");
        String previous = entries.isEmpty() ? GENESIS : entries.get(entries.size()-1).hash();
        int sequence = entries.size()+1;
        Entry entry = new Entry(sequence, previous, payload,
                sha256(sequence + "\n" + previous + "\n" + payload));
        entries.add(entry);
        return entry;
    }
    public synchronized List<Entry> entries() { return List.copyOf(entries); }

    public synchronized boolean verify() {
        String previous = GENESIS;
        int sequence = 1;
        for (Entry entry : entries) {
            if (entry.sequence() != sequence || !entry.previousHash().equals(previous)) return false;
            if (!entry.hash().equals(sha256(entry.sequence() + "\n" + entry.previousHash() + "\n" + entry.payload()))) return false;
            previous = entry.hash(); sequence++;
        }
        return true;
    }
    synchronized void replacePayloadForTest(int index, String replacement) {
        Entry old = entries.get(index);
        entries.set(index, new Entry(old.sequence(), old.previousHash(), replacement, old.hash()));
    }
    private static String sha256(String text) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }
    public record Entry(int sequence, String previousHash, String payload, String hash) { }
}
