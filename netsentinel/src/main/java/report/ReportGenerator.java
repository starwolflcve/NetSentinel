package report;

import model.Alert;
import model.Severity;

import java.io.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

public class ReportGenerator {

    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final String REPORT_PATH  = "logs/rapport_securite.txt";
    private static final String BLOCKER_PATH = "logs/regles_blocage.txt";

    /**
     * Génère le rapport complet (4.2) et les règles de blocage (4.3).
     */
    public void generate(List<Alert> alerts) {
        generateReport(alerts);
        generateBlockingRules(alerts);
    }

    // ── 4.2 Rapport de sécurité ─────────────────────────────────────────────

    public void generateReport(List<Alert> alerts) {
        try (PrintWriter pw = new PrintWriter(new FileWriter(REPORT_PATH))) {

            pw.println("═══════════════════════════════════════════════════════════");
            pw.println("           NETSENTINEL — RAPPORT D'ANALYSE SÉCURITÉ        ");
            pw.println("       Généré le : " + java.time.LocalDateTime.now().format(FMT));
            pw.println("═══════════════════════════════════════════════════════════");
            pw.println();

            // ── 1. Résumé exécutif
            pw.println("━━━ 1. RÉSUMÉ EXÉCUTIF ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            pw.println("Nombre total d'alertes : " + alerts.size());
            pw.println();

            Map<Severity, Long> bySeverity = alerts.stream()
                .collect(Collectors.groupingBy(Alert::getSeverity, Collectors.counting()));

            for (Severity s : Severity.values()) {
                pw.printf("  %-10s : %d%n", s, bySeverity.getOrDefault(s, 0L));
            }
            pw.println();

            // IPs les plus dangereuses (top 5 par nombre d'alertes)
            pw.println("Top 5 des IPs les plus suspectes :");
            alerts.stream()
                .collect(Collectors.groupingBy(Alert::getSourceIp, Collectors.counting()))
                .entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(5)
                .forEach(e -> pw.printf("  %-18s → %d alerte(s)%n", e.getKey(), e.getValue()));
            pw.println();

            // ── 2. Timeline des incidents
            pw.println("━━━ 2. TIMELINE DES INCIDENTS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            List<Alert> sorted = alerts.stream()
                .sorted(Comparator.comparing(Alert::getTimestamp))
                .toList();

            for (Alert a : sorted) {
                pw.printf("[%s] %-10s %-12s IP: %-18s — %s%n",
                    a.getTimestamp().format(FMT),
                    a.getSeverity(),
                    a.getType(),
                    a.getSourceIp(),
                    truncate(a.getDescription(), 80));
            }
            pw.println();

            // ── 3. Détail par IP suspecte
            pw.println("━━━ 3. DÉTAIL PAR IP SUSPECTE ━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            Map<String, List<Alert>> byIp = alerts.stream()
                .collect(Collectors.groupingBy(Alert::getSourceIp));

            byIp.entrySet().stream()
                .sorted((a, b) -> b.getValue().size() - a.getValue().size())
                .forEach(entry -> {
                    String ip = entry.getKey();
                    List<Alert> ipAlerts = entry.getValue();
                    Severity maxSev = ipAlerts.stream()
                        .map(Alert::getSeverity)
                        .max(Comparator.naturalOrder())
                        .orElse(Severity.LOW);

                    pw.printf("%nIP: %-18s  |  Alertes: %d  |  Sévérité max: %s%n",
                        ip, ipAlerts.size(), maxSev);
                    pw.println("  Types déclenchés : " +
                        ipAlerts.stream().map(Alert::getType).collect(Collectors.toSet()));

                    for (Alert a : ipAlerts) {
                        pw.printf("    [%s] %s — %s (count: %d)%n",
                            a.getSeverity(), a.getType(),
                            truncate(a.getDescription(), 70), a.getCount());
                    }
                });
            pw.println();

            // ── 4. Recommandations
            pw.println("━━━ 4. RECOMMANDATIONS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            pw.println(buildRecommendations(alerts));
            pw.println();
            pw.println("═══════════════════════════════════════════════════════════");
            pw.println("                   FIN DU RAPPORT                          ");
            pw.println("═══════════════════════════════════════════════════════════");

            System.out.println("[ReportGenerator] Rapport généré : " + REPORT_PATH);

        } catch (IOException e) {
            System.err.println("[ReportGenerator] Erreur écriture rapport : " + e.getMessage());
        }
    }

    // ── 4.3 Règles de blocage ────────────────────────────────────────────────

    public void generateBlockingRules(List<Alert> alerts) {
        // Garder uniquement les IPs HIGH ou CRITICAL
        Set<String> dangerousIps = alerts.stream()
            .filter(a -> a.getSeverity() == Severity.HIGH || a.getSeverity() == Severity.CRITICAL)
            .map(Alert::getSourceIp)
            .collect(Collectors.toSet());

        if (dangerousIps.isEmpty()) {
            System.out.println("[ReportGenerator] Aucune IP HIGH/CRITICAL — pas de règle de blocage.");
            return;
        }

        try (PrintWriter pw = new PrintWriter(new FileWriter(BLOCKER_PATH))) {
            pw.println("# ═══════════════════════════════════════════");
            pw.println("# NETSENTINEL — RÈGLES DE BLOCAGE AUTOMATIQUES");
            pw.println("# Généré le : " + java.time.LocalDateTime.now().format(FMT));
            pw.println("# IPs classées HIGH ou CRITICAL");
            pw.println("# ═══════════════════════════════════════════");
            pw.println();

            // iptables
            pw.println("# --- iptables (Linux) ---");
            for (String ip : dangerousIps) {
                pw.println("iptables -A INPUT -s " + ip + " -j DROP");
            }
            pw.println();

            // nginx
            pw.println("# --- nginx (deny directive) ---");
            for (String ip : dangerousIps) {
                pw.println("deny " + ip + ";");
            }
            pw.println();

            // Apache
            pw.println("# --- Apache (.htaccess) ---");
            pw.println("Order Deny,Allow");
            for (String ip : dangerousIps) {
                pw.println("Deny from " + ip);
            }
            pw.println();

            // Résumé
            pw.println("# " + dangerousIps.size() + " IP(s) à bloquer.");

            System.out.println("[ReportGenerator] Règles de blocage générées : " + BLOCKER_PATH
                + " (" + dangerousIps.size() + " IP(s))");

        } catch (IOException e) {
            System.err.println("[ReportGenerator] Erreur écriture blocage : " + e.getMessage());
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private String buildRecommendations(List<Alert> alerts) {
        Set<String> types = alerts.stream()
            .map(Alert::getType)
            .collect(Collectors.toSet());

        StringBuilder sb = new StringBuilder();

        if (types.contains("BRUTE_FORCE")) {
            sb.append("""
                [BRUTE_FORCE]
                  → Activer le verrouillage de compte après 5 échecs (fail2ban, auth lockout).
                  → Implémenter une authentification MFA.
                  → Limiter les connexions par IP (rate limiting).

                """);
        }
        if (types.contains("SQL_INJECTION")) {
            sb.append("""
                [SQL_INJECTION]
                  → Utiliser des requêtes préparées (PreparedStatement) sans exception.
                  → Mettre en place un WAF (Web Application Firewall).
                  → Valider et sanitiser toutes les entrées utilisateur.

                """);
        }
        if (types.contains("DDOS")) {
            sb.append("""
                [DDOS]
                  → Déployer un CDN avec protection DDoS (Cloudflare, AWS Shield).
                  → Configurer des seuils de connexion sur le pare-feu.
                  → Activer le rate-limiting au niveau du load balancer.

                """);
        }
        if (types.contains("PORT_SCAN") || types.contains("SCAN")) {
            sb.append("""
                [PORT_SCAN / SCAN]
                  → Fermer tous les ports inutilisés sur le pare-feu.
                  → Activer les règles de détection de scan (portsentry, snort).
                  → Surveiller les connexions répétées sur des ports fermés.

                """);
        }
        if (sb.isEmpty()) {
            sb.append("Aucune recommandation spécifique — continuer la surveillance standard.");
        }
        return sb.toString().trim();
    }

    private String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max - 1) + "…" : s;
    }
}