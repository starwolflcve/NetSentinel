package detector;

import model.Alert;
import model.LogEntry;
import model.Severity;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ScanDetector implements ThreatDetector {
    
    // Chemins typiques de scan
    private static final Set<String> SUSPICIOUS_PATHS = new HashSet<>(Arrays.asList(
        "/admin", "/wp-login.php", "/.env", "/phpmyadmin",
        "/config.yml", "/.git/config", "/backup.sql",
        "/administrator", "/wp-admin", "/mysql",
        "/phpmyadmin/index.php", "/admin.php", "/login.php",
        "/robots.txt", "/sitemap.xml", "/.htaccess",
        "/web.config", "/config.php", "/database.yml",
        "/.svn/entries", "/.hg/hgrc", "/CVS/Root",
        "/etc/passwd", "/proc/version", "/windows/win.ini"
    ));
    
    // User-agents d'outils de scan
    private static final Set<String> SUSPICIOUS_USER_AGENTS = new HashSet<>(Arrays.asList(
        "sqlmap", "nikto", "nmap", "dirbuster", "gobuster",
        "burp", "owasp", "acunetix", "nessus", "openvas",
        "zap", "w3af", "skipfish", "arachni", "metasploit",
        "python-requests", "curl", "wget", "perl", "java/"
    ));
    
    private static final int SCAN_THRESHOLD_404 = 20;
    
    @Override
    public List<Alert> detect(List<LogEntry> entries) {
        List<Alert> alerts = new ArrayList<>();
        
        // Détecter les scans par chemins suspects
        detectPathScans(entries, alerts);
        
        // Détecter les scans par user-agents
        detectUserAgentScans(entries, alerts);
        
        // Détecter les scans par 404 multiples
        detect404Scans(entries, alerts);
        
        return alerts;
    }
    
    private void detectPathScans(List<LogEntry> entries, List<Alert> alerts) {
        Map<String, Integer> ipSuspiciousCount = new HashMap<>();
        Map<String, String> ipLastPath = new HashMap<>();
        Map<String, LocalDateTime> ipLastTimestamp = new HashMap<>();
        
        for (LogEntry entry : entries) {
            String url = entry.getUrl().toLowerCase();
            String ip = entry.getIp();
            
            // Vérifier si l'URL contient un chemin suspect
            for (String suspiciousPath : SUSPICIOUS_PATHS) {
                if (url.contains(suspiciousPath)) {
                    ipSuspiciousCount.merge(ip, 1, Integer::sum);
                    ipLastPath.put(ip, suspiciousPath);
                    ipLastTimestamp.put(ip, entry.getTimestamp());
                    
                    // Générer une alerte si on a plusieurs accès à des chemins suspects
                    if (ipSuspiciousCount.get(ip) >= 3) {
                        Alert alert = new Alert(
                            "SCAN_PATH",
                            String.format("Scan de vulnérabilités détecté : accès à %d chemins suspects (dernier: %s)", 
                                        ipSuspiciousCount.get(ip), suspiciousPath),
                            Severity.MEDIUM,
                            ip,
                            entry.getTimestamp(),
                            ipSuspiciousCount.get(ip)
                        );
                        
                        alerts.add(alert);
                    }
                    break;
                }
            }
        }
    }
    
    private void detectUserAgentScans(List<LogEntry> entries, List<Alert> alerts) {
        Map<String, Integer> ipScanCount = new HashMap<>();
        Map<String, String> ipLastUserAgent = new HashMap<>();
        Map<String, LocalDateTime> ipLastTimestamp = new HashMap<>();
        
        for (LogEntry entry : entries) {
            String userAgent = entry.getUserAgent().toLowerCase();
            String ip = entry.getIp();
            
            // Vérifier si le user-agent correspond à un outil de scan
            for (String suspiciousUA : SUSPICIOUS_USER_AGENTS) {
                if (userAgent.contains(suspiciousUA)) {
                    ipScanCount.merge(ip, 1, Integer::sum);
                    ipLastUserAgent.put(ip, entry.getUserAgent());
                    ipLastTimestamp.put(ip, entry.getTimestamp());
                    
                    // Générer une alerte
                    Alert alert = new Alert(
                        "SCAN_USER_AGENT",
                        String.format("Outil de scan détecté : %s (requêtes: %d)", 
                                    entry.getUserAgent(), ipScanCount.get(ip)),
                        Severity.HIGH,
                        ip,
                        entry.getTimestamp(),
                        ipScanCount.get(ip)
                    );
                    
                    alerts.add(alert);
                    break;
                }
            }
        }
    }
    
    private void detect404Scans(List<LogEntry> entries, List<Alert> alerts) {
        Map<String, Integer> ip404Count = new HashMap<>();
        Map<String, Set<String>> ipUrls = new HashMap<>();
        Map<String, LocalDateTime> ipLastTimestamp = new HashMap<>();
        
        for (LogEntry entry : entries) {
            if (entry.getStatusCode() == 404) {
                String ip = entry.getIp();
                String url = entry.getUrl();
                
                ip404Count.merge(ip, 1, Integer::sum);
                ipUrls.computeIfAbsent(ip, k -> new HashSet<>()).add(url);
                ipLastTimestamp.put(ip, entry.getTimestamp());
                
                // Vérifier si on a assez d'URLs différentes en 404
                if (ipUrls.get(ip).size() >= SCAN_THRESHOLD_404) {
                    Alert alert = new Alert(
                        "SCAN_404",
                        String.format("Scan de répertoires détecté : %d URLs différentes en 404", 
                                    ipUrls.get(ip).size()),
                        Severity.MEDIUM,
                        ip,
                        entry.getTimestamp(),
                        ipUrls.get(ip).size()
                    );
                    
                    alerts.add(alert);
                }
            }
        }
    }
    
    @Override
    public String getDetectorName() {
        return "Scan Detector";
    }
}
