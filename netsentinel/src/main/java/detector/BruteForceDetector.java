package detector;

import model.Alert;
import model.LogEntry;
import model.Severity;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class BruteForceDetector implements ThreatDetector {
    
    private static final int BRUTE_FORCE_THRESHOLD = 10;
    private static final int HIGH_SEVERITY_THRESHOLD = 50;
    private static final int TIME_WINDOW_MINUTES = 5;
    
    @Override
    public List<Alert> detect(List<LogEntry> entries) {
        List<Alert> alerts = new ArrayList<>();
        
        // Grouper les entrées par IP
        Map<String, List<LogEntry>> ipEntries = new HashMap<>();
        for (LogEntry entry : entries) {
            ipEntries.computeIfAbsent(entry.getIp(), k -> new ArrayList<>()).add(entry);
        }
        
        // Analyser chaque IP pour détecter les tentatives de brute force
        for (Map.Entry<String, List<LogEntry>> ipEntry : ipEntries.entrySet()) {
            String ip = ipEntry.getKey();
            List<LogEntry> ipLogs = ipEntry.getValue();
            
            // Trier par timestamp
            ipLogs.sort((a, b) -> a.getTimestamp().compareTo(b.getTimestamp()));
            
            // Analyser les fenêtres de temps
            for (int i = 0; i < ipLogs.size(); i++) {
                LocalDateTime windowStart = ipLogs.get(i).getTimestamp();
                LocalDateTime windowEnd = windowStart.plusMinutes(TIME_WINDOW_MINUTES);
                
                int suspiciousCount = 0;
                LocalDateTime lastAttempt = null;
                
                // Compter les réponses 401 ou 403 dans la fenêtre de temps
                for (int j = i; j < ipLogs.size() && !ipLogs.get(j).getTimestamp().isAfter(windowEnd); j++) {
                    LogEntry log = ipLogs.get(j);
                    int statusCode = log.getStatusCode();
                    
                    if (statusCode == 401 || statusCode == 403) {
                        suspiciousCount++;
                        lastAttempt = log.getTimestamp();
                    }
                }
                
                // Générer une alerte si le seuil est dépassé
                if (suspiciousCount >= BRUTE_FORCE_THRESHOLD) {
                    Severity severity = suspiciousCount >= HIGH_SEVERITY_THRESHOLD ? Severity.HIGH : Severity.MEDIUM;
                    
                    Alert alert = new Alert(
                        "BRUTE_FORCE",
                        String.format("Tentatives de connexion par force brute détectées : %d requêtes 401/403 en %d minutes", 
                                    suspiciousCount, TIME_WINDOW_MINUTES),
                        severity,
                        ip,
                        lastAttempt != null ? lastAttempt : windowStart,
                        suspiciousCount
                    );
                    
                    alerts.add(alert);
                    
                    // Avancer pour éviter les alertes en double
                    i += suspiciousCount - 1;
                }
            }
        }
        
        return alerts;
    }
    
    @Override
    public String getDetectorName() {
        return "Brute Force Detector";
    }
}
