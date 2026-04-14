package detector;

import model.Alert;
import model.LogEntry;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

public class BruteForceDetectorTest {

    @Test
    public void testDetectBruteForce() {
        BruteForceDetector detector = new BruteForceDetector();
        List<LogEntry> entries = new ArrayList<>();
        LocalDateTime baseTime = LocalDateTime.now();

        // Add 15 failed login attempts within 5 minutes
        for (int i = 0; i < 15; i++) {
            entries.add(new LogEntry("192.168.1.1", "-", baseTime.plusSeconds(i), "POST", "/login", "HTTP/1.1", 401, 0, "-", "-"));
        }

        List<Alert> alerts = detector.detect(entries);

        assertFalse(alerts.isEmpty());
        assertEquals("BRUTE_FORCE", alerts.get(0).getType());
    }

    @Test
    public void testNoBruteForce() {
        BruteForceDetector detector = new BruteForceDetector();
        List<LogEntry> entries = new ArrayList<>();
        LocalDateTime baseTime = LocalDateTime.now();

        // Add only 5 failed attempts, below threshold
        for (int i = 0; i < 5; i++) {
            entries.add(new LogEntry("192.168.1.1", "-", baseTime.plusSeconds(i), "POST", "/login", "HTTP/1.1", 401, 0, "-", "-"));
        }

        List<Alert> alerts = detector.detect(entries);

        assertTrue(alerts.isEmpty());
    }
}