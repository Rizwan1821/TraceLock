package dev.rizwan.tracelock;

import dev.rizwan.tracelock.audit.HashChainJournal;
import dev.rizwan.tracelock.detect.DetectionRule;
import dev.rizwan.tracelock.detect.FailureThenSuccessRule;
import dev.rizwan.tracelock.detect.PasswordSprayRule;
import dev.rizwan.tracelock.io.CsvEventReader;
import dev.rizwan.tracelock.model.Finding;
import dev.rizwan.tracelock.model.SecurityEvent;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/** Defensive local authentication-event triage. Does not access remote systems. */
public final class TraceLock {
    private TraceLock() { }
    public static void main(String[] args) {
        if (args.length != 1 || args[0].equals("--help")) {
            System.out.println("TraceLock — explainable authentication-event triage");
            System.out.println("Usage: java -jar target/tracelock-1.0.0.jar <events.csv>");
            System.out.println("CSV: timestamp,event_id,username,source_ip,type,success,detail");
            return;
        }
        try { run(Path.of(args[0])); }
        catch (Exception ex) {
            System.err.println("TraceLock error: " + ex.getMessage());
            System.exit(2);
        }
    }
    public static void run(Path csvPath) throws Exception {
        List<SecurityEvent> events = CsvEventReader.read(csvPath);
        List<DetectionRule> rules = List.of(
                new PasswordSprayRule(4, Duration.ofMinutes(10)),
                new FailureThenSuccessRule(3, Duration.ofMinutes(15)));
        List<Finding> findings = new ArrayList<>();
        for (DetectionRule rule : rules) findings.addAll(rule.evaluate(events));
        findings.sort(Comparator.comparing(Finding::severity).reversed().thenComparing(Finding::firstSeen));

        HashChainJournal journal = new HashChainJournal();
        journal.append("ANALYSIS_START|events=" + events.size());
        for (Finding f : findings) journal.append("FINDING|" + f.ruleId() + "|" + f.severity()
                + "|" + f.username() + "|" + f.sourceIp() + "|evidence=" + String.join(";", f.evidenceEventIds()));
        journal.append("ANALYSIS_END|findings=" + findings.size());

        System.out.println("=== TraceLock Investigation Report ===");
        System.out.println("Events loaded : " + events.size());
        System.out.println("Findings      : " + findings.size() + "\n");
        if (findings.isEmpty()) {
            System.out.println("No configured patterns detected. This is not proof the dataset is benign.\n");
        } else {
            for (int i = 0; i < findings.size(); i++) {
                Finding f = findings.get(i);
                System.out.printf("%d. [%s] %s%n", i+1, f.severity(), f.title());
                System.out.printf("   Rule      : %s%n", f.ruleId());
                System.out.printf("   Account   : %s%n", f.username());
                System.out.printf("   Source IP : %s%n", f.sourceIp());
                System.out.printf("   Window    : %s — %s%n", f.firstSeen(), f.lastSeen());
                System.out.printf("   Why       : %s%n", f.explanation());
                System.out.printf("   Evidence  : %s%n%n", String.join(", ", f.evidenceEventIds()));
            }
        }
        System.out.println("Audit journal: " + journal.entries().size() + " entries; hash-chain valid = " + journal.verify());
        System.out.println("Note: findings are heuristics and require analyst validation.");
    }
}
