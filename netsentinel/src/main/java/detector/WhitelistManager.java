package detector;

import java.io.*;
import java.nio.file.*;
import java.util.HashSet;
import java.util.Set;

public class WhitelistManager {

    private final Set<String> whitelistedIps = new HashSet<>();
    private static final String DEFAULT_WHITELIST_PATH = "logs/whitelist.txt";

    public WhitelistManager() {
        loadOrCreate(DEFAULT_WHITELIST_PATH);
    }

    public WhitelistManager(String filePath) {
        loadOrCreate(filePath);
    }

    /**
     * Charge la whitelist depuis un fichier, ou crée un fichier d'exemple si absent.
     */
    private void loadOrCreate(String filePath) {
        Path path = Paths.get(filePath);
        if (!Files.exists(path)) {
            createDefaultWhitelist(filePath);
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                // Ignorer les commentaires et lignes vides
                if (!line.isEmpty() && !line.startsWith("#")) {
                    whitelistedIps.add(line);
                }
            }
            System.out.println("[WhitelistManager] " + whitelistedIps.size() + " IP(s) whitelistée(s) chargées.");
        } catch (IOException e) {
            System.err.println("[WhitelistManager] Erreur lecture whitelist : " + e.getMessage());
        }
    }

    /**
     * Crée un fichier whitelist.txt d'exemple avec quelques IPs internes.
     */
    private void createDefaultWhitelist(String filePath) {
        try {
            Files.createDirectories(Paths.get(filePath).getParent());
            try (PrintWriter pw = new PrintWriter(filePath)) {
                pw.println("# Whitelist NetSentinel — une IP par ligne");
                pw.println("# Les IPs listées ici ne déclencheront jamais d'alerte");
                pw.println("127.0.0.1");
                pw.println("192.168.1.1");
                pw.println("10.0.0.1");
            }
            System.out.println("[WhitelistManager] Fichier whitelist créé : " + filePath);
        } catch (IOException e) {
            System.err.println("[WhitelistManager] Erreur création whitelist : " + e.getMessage());
        }
    }

    /** Retourne true si l'IP est whitelistée. */
    public boolean isWhitelisted(String ip) {
        return whitelistedIps.contains(ip);
    }

    /** Filtre une liste d'alertes en retirant celles dont l'IP est whitelistée. */
    public java.util.List<model.Alert> filter(java.util.List<model.Alert> alerts) {
        return alerts.stream()
            .filter(a -> !isWhitelisted(a.getSourceIp()))
            .toList();
    }

    public Set<String> getWhitelistedIps() {
        return java.util.Collections.unmodifiableSet(whitelistedIps);
    }
}