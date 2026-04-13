package detector;

import model.Alert;
import model.LogEntry;
import model.Severity;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DDoSDetector implements ThreatDetector {
    
    private static final int TIME_WINDOW_SECONDS = 10;
    private static final int IP_THRESHOLD_MULTIPLIER = 10;
    private static final int GLOBAL_THRESHOLD_MULTIPLIER = 50;
    
    @Override
    public List<Alert> detect(List<LogEntry> entries) {
        List<Alert> alerts = new ArrayList<>();
        
        if (entries.isEmpty()) {
            return alerts;
        }
        
        // Calculer la durée totale et la moyenne de requêtes par seconde
        LocalDateTime startTime = entries.get(0).getTimestamp();
        LocalDateTime endTime = entries.get(entries.size() - 1).getTimestamp();
        long totalSeconds = ChronoUnit.SECONDS.between(startTime, endTime);
        
        if (totalSeconds == 0) {
            totalSeconds = 1; // Éviter la division par zéro
        }
        
        double avgRequestsPerSecond = (double) entries.size() / totalSeconds;
        
        // Détecter les attaques DDoS par IP
        detectIPBasedDDoS(entries, avgRequestsPerSecond, alerts);
        
        // Détecter les attaques DDoS distribuées (volume global)
        detectGlobalDDoS(entries, avgRequestsPerSecond, alerts);
        
        return alerts;
    }
    
    private void detectIPBasedDDoS(List<LogEntry> entries, double avgRequestsPerSecond, List<Alert> alerts) {
        // Grouper les entrées par IP
        Map<String, List<LogEntry>> ipEntries = new HashMap<>();
        for (LogEntry entry : entries) {
            ipEntries.computeIfAbsent(entry.getIp(), k -> new ArrayList<>()).add(entry);
        }
        
        // Analyser chaque IP
        for (Map.Entry<String, List<LogEntry>> ipEntry : ipEntries.entrySet()) {
            String ip = ipEntry.getKey();
            List<LogEntry> ipLogs = ipEntry.getValue();
            
            // Trier par timestamp
            ipLogs.sort((a, b) -> a.getTimestamp().compareTo(b.getTimestamp()));
            
            // Analyser les fenêtres de temps
            for (int i = 0; i < ipLogs.size(); i++) {
                LocalDateTime windowStart = ipLogs.get(i).getTimestamp();
                LocalDateTime windowEnd = windowStart.plusSeconds(TIME_WINDOW_SECONDS);
                
                int requestCount = 0;
                LocalDateTime lastRequest = null;
                
                // Compter les requêtes dans la fenêtre de temps
                for (int j = i; j < ipLogs.size() && !ipLogs.get(j).getTimestamp().isAfter(windowEnd); j++) {
                    requestCount++;
                    lastRequest = ipLogs.get(j).getTimestamp();
                }
                
                double requestsPerSecond = (double) requestCount / TIME_WINDOW_SECONDS;
                
                // Vérifier si l'IP dépasse le seuil
                if (requestsPerSecond > avgRequestsPerSecond * IP_THRESHOLD_MULTIPLIER) {
                    Alert alert = new Alert(
                        "DDOS_IP",
                        String.format("Attaque DDoS détectée depuis l'IP %s : %.2f req/s (seuil: %.2f req/s)", 
                                    ip, requestsPerSecond, avgRequestsPerSecond * IP_THRESHOLD_MULTIPLIER),
                        Severity.HIGH,
                        ip,
                        lastRequest != null ? lastRequest : windowStart,
                        requestCount
                    );
                    
                    alerts.add(alert);
                    
                    // Avancer pour éviter les alertes en double
                    i += requestCount - 1;
                }
            }
        }
    }
    
    private void detectGlobalDDoS(List<LogEntry> entries, double avgRequestsPerSecond, List<Alert> alerts) {
        // Trier toutes les entrées par timestamp
        List<LogEntry> sortedEntries = new ArrayList<>(entries);
        sortedEntries.sort((a, b) -> a.getTimestamp().compareTo(b.getTimestamp()));
        
        // Analyser les fenêtres de temps globales
        for (int i = 0; i < sortedEntries.size(); i++) {
            LocalDateTime windowStart = sortedEntries.get(i).getTimestamp();
            LocalDateTime windowEnd = windowStart.plusSeconds(TIME_WINDOW_SECONDS);
            
            int requestCount = 0;
            LocalDateTime lastRequest = null;
            
            // Compter les requêtes globales dans la fenêtre de temps
            for (int j = i; j < sortedEntries.size() && !sortedEntries.get(j).getTimestamp().isAfter(windowEnd); j++) {
                requestCount++;
                lastRequest = sortedEntries.get(j).getTimestamp();
            }
            
            double requestsPerSecond = (double) requestCount / TIME_WINDOW_SECONDS;
            
            // Vérifier si le volume global dépasse le seuil critique
            if (requestsPerSecond > avgRequestsPerSecond * GLOBAL_THRESHOLD_MULTIPLIER) {
                Alert alert = new Alert(
                    "DDOS_DISTRIBUTED",
                    String.format("Attaque DDoS distribuée détectée : %.2f req/s globales (seuil critique: %.2f req/s)", 
                                requestsPerSecond, avgRequestsPerSecond * GLOBAL_THRESHOLD_MULTIPLIER),
                    Severity.CRITICAL,
                    "MULTIPLE_IPS",
                    lastRequest != null ? lastRequest : windowStart,
                    requestCount
                );
                
                alerts.add(alert);
                
                // Avancer pour éviter les alertes en double
                i += requestCount - 1;
            }
        }
    }
    
    @Override
    public String getDetectorName() {
        return "DDoS Detector";
    }
}