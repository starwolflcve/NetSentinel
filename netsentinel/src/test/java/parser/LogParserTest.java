package parser;

import model.LogEntry;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.time.LocalDateTime;

public class LogParserTest {

    @Test
    public void testParseLineValid() {
        LogParser parser = new LogParser();
        String line = "192.168.1.1 - - [10/Oct/2000:13:55:36 -0700] \"GET /apache_pb.gif HTTP/1.0\" 200 2326 \"http://www.example.com/start.html\" \"Mozilla/4.08 [en] (Win98; I ;Nav)\"";

        LogEntry entry = parser.parseLine(line);

        assertNotNull(entry);
        assertEquals("192.168.1.1", entry.getIp());
        assertEquals("GET", entry.getMethod());
        assertEquals("/apache_pb.gif", entry.getUrl());
        assertEquals(200, entry.getStatusCode());
        assertEquals(2326, entry.getResponseSize());
    }

    @Test
    public void testParseLineInvalid() {
        LogParser parser = new LogParser();
        String invalidLine = "invalid log line";

        LogEntry entry = parser.parseLine(invalidLine);

        assertNull(entry);
    }
}