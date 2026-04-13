package dashboard;

import model.Alert;
import model.LogEntry;
import model.Severity;

import java.util.*;

public class Dashboard {

    public void display(List<LogEntry> entries) {
        System.out.println("\n========================================");
        System.out.println("        NETSENTINEL — DASHBOARD         ");
        System.out.println("========================================\n");

        // 1. Total
        System.out.println("Total de requêtes parsées : " + entries.size());

        // 2. Top 10 IPs
        System.out.println("\n--- Top 10 IPs les plus actives ---");
        Map<String, Integer> ipCount = new HashMap<>();
        for (LogEntry e : entries) {
            ipCount.merge(e.getIp(), 1, Integer::sum);
        }
        ipCount.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .limit(10)
            .forEach(entry -> System.out.println("  " + entry.getKey() + " → " + entry.getValue() + " requêtes"));

        // 3. Distribution codes HTTP
        System.out.println("\n--- Distribution des codes HTTP ---");
        Map<Integer, Integer> statusCount = new HashMap<>();
        for (LogEntry e : entries) {
            statusCount.merge(e.getStatusCode(), 1, Integer::sum);
        }
        statusCount.entrySet().stream()
            .sorted(Map.Entry.comparingByKey())
            .forEach(entry -> System.out.println("  HTTP " + entry.getKey() + " → " + entry.getValue()));

        // 4. Top 10 URLs
        System.out.println("\n--- Top 10 URLs les plus accédées ---");
        Map<String, Integer> urlCount = new HashMap<>();
        for (LogEntry e : entries) {
            urlCount.merge(e.getUrl(), 1, Integer::sum);
        }
        urlCount.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .limit(10)
            .forEach(entry -> System.out.println("  " + entry.getKey() + " → " + entry.getValue()));

        // 5. Top 5 User-Agents
        System.out.println("\n--- Top 5 User-Agents ---");
        Map<String, Integer> uaCount = new HashMap<>();
        for (LogEntry e : entries) {
            uaCount.merge(e.getUserAgent(), 1, Integer::sum);
        }
        uaCount.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .limit(5)
            .forEach(entry -> System.out.println("  " + entry.getKey() + " → " + entry.getValue()));

        System.out.println("\n========================================\n");
    }

    public void displayAlerts(List<Alert> alerts) {
        System.out.println("\n========================================");
        System.out.println("        NETSENTINEL — MENACES          ");
        System.out.println("========================================\n");

        displayAlertsBySeverity(alerts);

        // Résumé
        System.out.println("\n--- RÉSUMÉ DES ALERTES ---");
        System.out.println("Total d'alertes: " + alerts.size());
        System.out.println("Alertes CRITICAL: " + countAlertsBySeverity(alerts, Severity.CRITICAL));
        System.out.println("Alertes HIGH: " + countAlertsBySeverity(alerts, Severity.HIGH));
        System.out.println("Alertes MEDIUM: " + countAlertsBySeverity(alerts, Severity.MEDIUM));
        System.out.println("Alertes LOW: " + countAlertsBySeverity(alerts, Severity.LOW));
        System.out.println("\n========================================\n");
    }

    private void displayAlertsBySeverity(List<Alert> alerts) {
        if (alerts.isEmpty()) {
            System.out.println("✅ Aucune menace détectée!\n");
            return;
        }

        // Afficher les alertes CRITICAL
        System.out.println("\n🚨 ALERTES CRITICAL:");
        alerts.stream()
            .filter(alert -> alert.getSeverity() == Severity.CRITICAL)
            .forEach(alert -> System.out.println("  " + alert));

        // Afficher les alertes HIGH
        System.out.println("\n⚠️  ALERTES HIGH:");
        alerts.stream()
            .filter(alert -> alert.getSeverity() == Severity.HIGH)
            .forEach(alert -> System.out.println("  " + alert));

        // Afficher les alertes MEDIUM
        System.out.println("\n⚡ ALERTES MEDIUM:");
        alerts.stream()
            .filter(alert -> alert.getSeverity() == Severity.MEDIUM)
            .forEach(alert -> System.out.println("  " + alert));

        // Afficher les alertes LOW
        System.out.println("\n🔍 ALERTES LOW:");
        alerts.stream()
            .filter(alert -> alert.getSeverity() == Severity.LOW)
            .forEach(alert -> System.out.println("  " + alert));
    }

    private long countAlertsBySeverity(List<Alert> alerts, Severity severity) {
        return alerts.stream()
            .filter(alert -> alert.getSeverity() == severity)
            .count();
    }
}