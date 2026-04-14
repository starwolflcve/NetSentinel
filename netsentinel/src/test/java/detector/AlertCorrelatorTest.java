package detector;

import model.Alert;
import model.Severity;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;

public class AlertCorrelatorTest {

    @Test
    public void testCorrelateMultipleDetectors() {
        AlertCorrelator correlator = new AlertCorrelator();
        LocalDateTime now = LocalDateTime.now();

        Alert alert1 = new Alert("SQL_INJECTION", "SQL injection detected", Severity.MEDIUM, "192.168.1.1", now, 1);
        Alert alert2 = new Alert("BRUTE_FORCE", "Brute force detected", Severity.MEDIUM, "192.168.1.1", now, 1);
        Alert alert3 = new Alert("DDOS", "DDoS detected", Severity.MEDIUM, "192.168.1.1", now, 1);

        List<Alert> correlated = correlator.correlate(Arrays.asList(alert1, alert2, alert3));

        // Should upgrade to CRITICAL due to 3 detectors
        assertEquals(Severity.CRITICAL, correlated.get(0).getSeverity());
        assertTrue(correlated.get(0).getDescription().contains("CORRÉLÉ"));
    }

    @Test
    public void testCorrelateTwoDetectors() {
        AlertCorrelator correlator = new AlertCorrelator();
        LocalDateTime now = LocalDateTime.now();

        Alert alert1 = new Alert("SQL_INJECTION", "SQL injection detected", Severity.LOW, "192.168.1.1", now, 1);
        Alert alert2 = new Alert("BRUTE_FORCE", "Brute force detected", Severity.LOW, "192.168.1.1", now, 1);

        List<Alert> correlated = correlator.correlate(Arrays.asList(alert1, alert2));

        // Should upgrade from LOW to MEDIUM
        assertEquals(Severity.MEDIUM, correlated.get(0).getSeverity());
    }
}