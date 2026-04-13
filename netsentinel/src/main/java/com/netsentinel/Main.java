package com.netsentinel;

import dashboard.Dashboard;
import detector.BruteForceDetector;
import detector.DDoSDetector;
import detector.SQLInjectionDetector;
import detector.ScanDetector;
import model.Alert;
import model.LogEntry;
import parser.LogParser;

import java.util.ArrayList;
import java.util.List;

public class Main {

    public static void main(String[] args) {
        String filePath = "logs/access_log_clean.txt";

        // Parsing
        LogParser parser = new LogParser();
        List<LogEntry> entries = parser.parse(filePath);

        // Dashboard
        Dashboard dashboard = new Dashboard();
        dashboard.display(entries);

        // Initialiser les détecteurs
        List<detector.ThreatDetector> detectors = new ArrayList<>();
        detectors.add(new BruteForceDetector());
        detectors.add(new SQLInjectionDetector());
        detectors.add(new DDoSDetector());
        detectors.add(new ScanDetector());

        // Exécuter tous les détecteurs
        List<Alert> allAlerts = new ArrayList<>();
        for (detector.ThreatDetector detector : detectors) {
            System.out.println("Exécution du détecteur: " + detector.getDetectorName());
            List<Alert> alerts = detector.detect(entries);
            allAlerts.addAll(alerts);
            System.out.println("  → " + alerts.size() + " alerte(s) trouvée(s)\n");
        }

        // Afficher les alertes via le Dashboard
        dashboard.displayAlerts(allAlerts);
    }
}