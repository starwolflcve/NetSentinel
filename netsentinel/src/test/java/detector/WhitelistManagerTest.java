package detector;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.io.PrintWriter;

public class WhitelistManagerTest {

    @Test
    public void testIsWhitelisted() {
        // Create a temporary whitelist file
        String testFile = "test_whitelist.txt";
        try (PrintWriter pw = new PrintWriter(testFile)) {
            pw.println("192.168.1.1");
            pw.println("# This is a comment");
            pw.println("10.0.0.1");
        } catch (Exception e) {
            fail("Failed to create test file");
        }

        WhitelistManager manager = new WhitelistManager(testFile);

        assertTrue(manager.isWhitelisted("192.168.1.1"));
        assertTrue(manager.isWhitelisted("10.0.0.1"));
        assertFalse(manager.isWhitelisted("192.168.1.2"));

        // Clean up
        new File(testFile).delete();
    }
}