package detector;

import model.Alert;
import model.LogEntry;
import model.Severity;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;

public class SQLInjectionDetectorTest {

    @Test
    public void testDetectSQLInjection() {
        SQLInjectionDetector detector = new SQLInjectionDetector();
        LogEntry entry = new LogEntry("192.168.1.1", "-", LocalDateTime.now(), "GET", "/search?id=1' UNION SELECT * FROM users--", "HTTP/1.1", 200, 0, "-", "-");

        List<Alert> alerts = detector.detect(Arrays.asList(entry));

        assertFalse(alerts.isEmpty());
        assertEquals("SQL_INJECTION", alerts.get(0).getType());
        assertTrue(alerts.get(0).getSeverity() == Severity.MEDIUM || alerts.get(0).getSeverity() == Severity.HIGH || alerts.get(0).getSeverity() == Severity.CRITICAL);
    }

    @Test
    public void testNoSQLInjection() {
        SQLInjectionDetector detector = new SQLInjectionDetector();
        LogEntry entry = new LogEntry("192.168.1.1", "-", LocalDateTime.now(), "GET", "/search?q=normal", "HTTP/1.1", 200, 0, "-", "-");

        List<Alert> alerts = detector.detect(Arrays.asList(entry));

        assertTrue(alerts.isEmpty());
    }
}