package detector;

import model.Alert;
import model.Severity;

import java.util.*;

public class AlertCorrelator {

    /**
     * Corrèle les alertes par IP et augmente la sévérité si plusieurs détecteurs se déclenchent.
     * - 1 détecteur  → sévérité inchangée
     * - 2 détecteurs → sévérité +1 niveau
     * - 3+ détecteurs → automatiquement CRITICAL
     */
    public List<Alert> correlate(List<Alert> alerts) {
        // Grouper les alertes par IP
        Map<String, List<Alert>> alertsByIp = new HashMap<>();
        for (Alert alert : alerts) {
            alertsByIp
                .computeIfAbsent(alert.getSourceIp(), k -> new ArrayList<>())
                .add(alert);
        }

        List<Alert> correlated = new ArrayList<>();

        for (Map.Entry<String, List<Alert>> entry : alertsByIp.entrySet()) {
            String ip = entry.getKey();
            List<Alert> ipAlerts = entry.getValue();

            // Compter les détecteurs uniques déclenchés
            Set<String> triggeredDetectors = new HashSet<>();
            for (Alert a : ipAlerts) {
                triggeredDetectors.add(a.getType());
            }
            int detectorCount = triggeredDetectors.size();

            for (Alert a : ipAlerts) {
                Severity newSeverity;

                if (detectorCount >= 3) {
                    newSeverity = Severity.CRITICAL;
                } else if (detectorCount == 2) {
                    newSeverity = upgradeSeverity(a.getSeverity());
                } else {
                    newSeverity = a.getSeverity();
                }

                // Créer une nouvelle alerte avec la sévérité mise à jour
                Alert updated = new Alert(
                    a.getType(),
                    a.getDescription() + (detectorCount >= 2
                        ? String.format(" [CORRÉLÉ: %d détecteurs sur IP %s]", detectorCount, ip)
                        : ""),
                    newSeverity,
                    a.getSourceIp(),
                    a.getTimestamp(),
                    a.getCount()
                );
                correlated.add(updated);
            }
        }

        // Trier par timestamp
        correlated.sort(Comparator.comparing(Alert::getTimestamp));
        return correlated;
    }

    /**
     * Monte d'un niveau de sévérité : LOW → MEDIUM → HIGH → CRITICAL
     */
    private Severity upgradeSeverity(Severity current) {
        return switch (current) {
            case LOW    -> Severity.MEDIUM;
            case MEDIUM -> Severity.HIGH;
            case HIGH, CRITICAL -> Severity.CRITICAL;
        };
    }

    /**
     * Retourne un résumé du scoring par IP (utile pour le rapport).
     */
    public Map<String, Integer> getDetectorCountByIp(List<Alert> alerts) {
        Map<String, Set<String>> detectorsByIp = new HashMap<>();
        for (Alert a : alerts) {
            detectorsByIp
                .computeIfAbsent(a.getSourceIp(), k -> new HashSet<>())
                .add(a.getType());
        }
        Map<String, Integer> result = new HashMap<>();
        detectorsByIp.forEach((ip, set) -> result.put(ip, set.size()));
        return result;
    }
}