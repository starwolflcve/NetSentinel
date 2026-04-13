package dashboard;

import model.LogEntry;

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
}