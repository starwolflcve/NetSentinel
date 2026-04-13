package detector;

import model.Alert;
import model.LogEntry;

import java.util.List;

public interface ThreatDetector {
    /**
     * Détecte les menaces dans une liste d'entrées de log
     * @param entries Liste des entrées de log à analyser
     * @return Liste des alertes générées
     */
    List<Alert> detect(List<LogEntry> entries);
    
    /**
     * Retourne le nom du détecteur
     * @return Nom du détecteur
     */
    String getDetectorName();
}
