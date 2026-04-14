package com.netsentinel;

import dashboard.Dashboard;
import detector.*;
import model.Alert;
import model.LogEntry;
import parser.LogParser;
import report.ReportGenerator;

import java.util.ArrayList;
import java.util.List;

public class Main {

    public static void main(String[] args) {
        // Choisir le fichier à analyser (clean ou attack)
        String filePath = args.length > 0 ? args[0] : "logs/access_log_clean.txt";
        System.out.println("╔══════════════════════════════════════╗");
        System.out.println("║        NETSENTINEL — Analyse         ║");
        System.out.println("╚══════════════════════════════════════╝");
        System.out.println("Fichier analysé : " + filePath + "\n");

        // ── 1. Parsing
        LogParser parser = new LogParser();
        List<LogEntry> entries = parser.parse(filePath);

        // ── 2. Dashboard
        Dashboard dashboard = new Dashboard();
        dashboard.display(entries);

        // ── 3. Whitelist (4.4)
        WhitelistManager whitelist = new WhitelistManager();

        // ── 4. Détection
        List<ThreatDetector> detectors = new ArrayList<>();
        detectors.add(new BruteForceDetector());
        detectors.add(new SQLInjectionDetector());
        detectors.add(new DDoSDetector());
        detectors.add(new ScanDetector());

        List<Alert> allAlerts = new ArrayList<>();
        for (ThreatDetector detector : detectors) {
            System.out.println("Exécution du détecteur : " + detector.getDetectorName());
            List<Alert> alerts = detector.detect(entries);
            allAlerts.addAll(alerts);
            System.out.println("  → " + alerts.size() + " alerte(s)\n");
        }

        // ── 5. Filtrage whitelist (4.4)
        int avant = allAlerts.size();
        allAlerts = whitelist.filter(allAlerts);
        System.out.println("Whitelist : " + (avant - allAlerts.size())
            + " alerte(s) supprimée(s) sur " + avant + " totales.\n");

        // ── 6. Corrélation (4.1)
        AlertCorrelator correlator = new AlertCorrelator();
        List<Alert> correlatedAlerts = correlator.correlate(allAlerts);
        System.out.println("Corrélation terminée : " + correlatedAlerts.size() + " alerte(s) après scoring.\n");

        // ── 7. Affichage dashboard
        dashboard.displayAlerts(correlatedAlerts);

        // ── 8. Rapport + règles de blocage (4.2 + 4.3)
        ReportGenerator reporter = new ReportGenerator();
        reporter.generate(correlatedAlerts);

        System.out.println("\nAnalyse terminée. Fichiers générés dans logs/");
    }
}