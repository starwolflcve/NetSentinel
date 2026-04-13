package detector;

import model.Alert;
import model.LogEntry;
import model.Severity;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class SQLInjectionDetector implements ThreatDetector {
    
    // Patterns SQLi courants
    private static final String[] SQLI_PATTERNS = {
        // Union-based
        "(?i).*union.*select.*",
        "(?i).*select.*union.*",
        
        // Boolean-based blind
        "(?i).*'.*or.*'.*=.*",
        "(?i).*\".*or.*\".*=.*",
        "(?i).*1.*=.*1.*",
        "(?i).*true.*",
        "(?i).*and.*1.*=.*1.*",
        
        // Time-based blind
        "(?i).*sleep\\(.*\\).*",
        "(?i).*waitfor.*delay.*",
        "(?i).*benchmark\\(.*\\).*",
        
        // Error-based
        "(?i).*extractvalue\\(.*\\).*",
        "(?i).*updatexml\\(.*\\).*",
        "(?i).*floor\\(.*\\).*",
        
        // Stacked queries
        "(?i).*;.*drop.*",
        "(?i).*;.*insert.*",
        "(?i).*;.*update.*",
        "(?i).*;.*delete.*",
        
        // Comment-based
        "(?i).*--.*",
        "(?i).*#.*",
        "(?i).*\\/\\*.*\\*\\/.*",
        
        // Function-based
        "(?i).*concat\\(.*\\).*",
        "(?i).*char\\(.*\\).*",
        "(?i).*ascii\\(.*\\).*",
        "(?i).*ord\\(.*\\).*",
        
        // Encoding-based
        "(?i).*%27.*%27.*",
        "(?i).*%22.*%22.*",
        "(?i).*%3B.*",
        
        // Common SQL keywords
        "(?i).*information_schema.*",
        "(?i).*mysql.*",
        "(?i).*pg_.*",
        "(?i).*sysobjects.*",
        "(?i).*master\\.dbo.*",
        
        // Load file
        "(?i).*load_file\\(.*\\).*",
        "(?i).*into.*outfile.*"
    };
    
    @Override
    public List<Alert> detect(List<LogEntry> entries) {
        List<Alert> alerts = new ArrayList<>();
        
        for (LogEntry entry : entries) {
            String url = entry.getUrl().toLowerCase();
            
            // Vérifier chaque pattern SQLi
            for (String patternStr : SQLI_PATTERNS) {
                Pattern pattern = Pattern.compile(patternStr, Pattern.CASE_INSENSITIVE);
                if (pattern.matcher(url).matches()) {
                    
                    // Déterminer la sévérité basée sur le type d'attaque
                    Severity severity = determineSeverity(patternStr, url);
                    
                    Alert alert = new Alert(
                        "SQL_INJECTION",
                        "Tentative d'injection SQL détectée dans l'URL: " + entry.getUrl(),
                        severity,
                        entry.getIp(),
                        entry.getTimestamp(),
                        1
                    );
                    
                    alerts.add(alert);
                    break; // Une alerte par entrée suffit
                }
            }
        }
        
        return alerts;
    }
    
    private Severity determineSeverity(String pattern, String url) {
        // Attaques plus dangereuses = HIGH severity
        if (pattern.contains("drop") || pattern.contains("delete") || 
            pattern.contains("update") || pattern.contains("insert") ||
            pattern.contains("information_schema") || pattern.contains("load_file")) {
            return Severity.HIGH;
        }
        
        // Attaques de type union ou time-based = MEDIUM severity
        if (pattern.contains("union") || pattern.contains("sleep") || 
            pattern.contains("benchmark") || pattern.contains("waitfor")) {
            return Severity.MEDIUM;
        }
        
        // Autres patterns = LOW severity
        return Severity.LOW;
    }
    
    @Override
    public String getDetectorName() {
        return "SQL Injection Detector";
    }
}
