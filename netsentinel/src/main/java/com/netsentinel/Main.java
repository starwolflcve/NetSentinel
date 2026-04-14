package com.netsentinel;

import dashboard.Dashboard;
import detector.*;
import model.Alert;
import model.LogEntry;
import parser.LogParser;
import report.ReportGenerator;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;

public class Main {

    private static final String DEFAULT_INPUT_LOG = "logs/access_log_clean.txt";
    private static final String DEFAULT_OUTPUT_REPORT = "rapport_securite.txt";

    public static void main(String[] args) {
        String inputLogPath = args.length > 0 ? args[0] : DEFAULT_INPUT_LOG;
        String outputReportPath = args.length > 1 ? args[1] : DEFAULT_OUTPUT_REPORT;

        try {
            runAnalysis(inputLogPath, outputReportPath);
            System.out.println("\nAnalyse terminée.");
            System.out.println("Rapport disponible : " + outputReportPath);
        } catch (Exception e) {
            System.err.println("Erreur pendant l'analyse : " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static void runAnalysis(String inputLogPath, String outputReportPath) throws IOException {
        Path inputPath = Paths.get(inputLogPath);
        Path outputPath = Paths.get(outputReportPath);

        if (!Files.exists(inputPath)) {
            throw new IOException("Fichier de logs introuvable : " + inputLogPath);
        }

        if (outputPath.getParent() != null) {
            Files.createDirectories(outputPath.getParent());
        }

        System.out.println("╔══════════════════════════════════════╗");
        System.out.println("║       NETSENTINEL — Analyse         ║");
        System.out.println("╚══════════════════════════════════════╝");
        System.out.println("Fichier analysé : " + inputLogPath + "\n");

        // 1. Parsing
        LogParser parser = new LogParser();
        List<LogEntry> entries = parser.parse(inputLogPath);

        // 2. Dashboard
        Dashboard dashboard = new Dashboard();
        dashboard.display(entries);

        // 3. Whitelist
        WhitelistManager whitelist = new WhitelistManager();

        // 4. Détection
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
            System.out.println(" → " + alerts.size() + " alerte(s)\n");
        }

        // 5. Filtrage whitelist
        int avant = allAlerts.size();
        allAlerts = whitelist.filter(allAlerts);
        System.out.println("Whitelist : " + (avant - allAlerts.size())
                + " alerte(s) supprimée(s) sur " + avant + " totales.\n");

        // 6. Corrélation
        AlertCorrelator correlator = new AlertCorrelator();
        List<Alert> correlatedAlerts = correlator.correlate(allAlerts);
        System.out.println("Corrélation terminée : " + correlatedAlerts.size()
                + " alerte(s) après scoring.\n");

        // 7. Affichage des alertes
        dashboard.displayAlerts(correlatedAlerts);

        // 8. Génération du rapport
        ReportGenerator reporter = new ReportGenerator();
        reporter.generate(correlatedAlerts);

        // 9. Copie du rapport généré vers le chemin demandé par le site
        Path generatedReport = findGeneratedReport();
        Files.copy(generatedReport, outputPath, StandardCopyOption.REPLACE_EXISTING);
    }

    private static Path findGeneratedReport() throws IOException {
        Path[] candidates = new Path[] {
                Paths.get("rapport_securite.txt"),
                Paths.get("logs", "rapport_securite.txt"),
                Paths.get("target", "rapport_securite.txt")
        };

        for (Path candidate : candidates) {
            if (Files.exists(candidate)) {
                return candidate;
            }
        }

        throw new IOException("Rapport généré introuvable après l'analyse.");
    }
}