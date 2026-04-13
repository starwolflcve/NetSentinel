package parser;

import model.LogEntry;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LogParser {

    // Regex Apache Combined Log Format
    private static final String LOG_PATTERN =
        "^(\\S+) \\S+ (\\S+) \\[(.+?)\\] \"(\\S+) (\\S+) (\\S+)\" (\\d{3}) (\\S+) \"(.*?)\" \"(.*?)\"$";

    private static final Pattern PATTERN = Pattern.compile(LOG_PATTERN);

    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern(
        "dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH
    );

    public List<LogEntry> parse(String filePath) {
        List<LogEntry> entries = new ArrayList<>();
        int errorCount = 0;

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            int lineNumber = 0;

            while ((line = reader.readLine()) != null) {
                lineNumber++;
                try {
                    LogEntry entry = parseLine(line);
                    if (entry != null) {
                        entries.add(entry);
                    }
                } catch (Exception e) {
                    errorCount++;
                    System.err.println("Ligne " + lineNumber + " ignorée : " + e.getMessage());
                }
            }

        } catch (IOException e) {
            System.err.println("Erreur lecture fichier : " + e.getMessage());
        }

        System.out.println("Parsing terminé : " + entries.size() + " entrées, " + errorCount + " erreurs.");
        return entries;
    }

    public LogEntry parseLine(String line) {
        Matcher matcher = PATTERN.matcher(line);

        if (!matcher.matches()) {
            return null;
        }

        String ip           = matcher.group(1);
        String user         = matcher.group(2);
        String rawDate      = matcher.group(3);
        String method       = matcher.group(4);
        String url          = matcher.group(5);
        String protocol     = matcher.group(6);
        int statusCode      = Integer.parseInt(matcher.group(7));
        String rawSize      = matcher.group(8);
        String referer      = matcher.group(9);
        String userAgent    = matcher.group(10);

        long responseSize = rawSize.equals("-") ? 0 : Long.parseLong(rawSize);
        LocalDateTime timestamp = LocalDateTime.parse(rawDate, FORMATTER);

        return new LogEntry(ip, user, timestamp, method, url, protocol,
                            statusCode, responseSize, referer, userAgent);
    }
}