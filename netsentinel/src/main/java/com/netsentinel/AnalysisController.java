package com.netsentinel;

import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.nio.file.*;

@RestController
@CrossOrigin(origins = "*")
public class AnalysisController {

    @PostMapping("/analyze")
    public ResponseEntity<byte[]> analyze(@RequestParam("file") MultipartFile file) {
        try {
            // Créer un dossier temporaire pour isoler chaque analyse
            Path workDir = Files.createTempDirectory("netsentinel_");
            Path logFile = workDir.resolve("access_log.txt");
            Path reportPath = workDir.resolve("rapport_securite.txt");

            // Sauvegarder le fichier glissé-déposé
            file.transferTo(logFile.toFile());

            // Lancer ton analyseur sur ce fichier spécifique
            Main.runAnalysis(logFile.toString(), reportPath.toString());

            // Récupérer le rapport généré
            byte[] reportBytes = Files.readAllBytes(reportPath);

            // Nettoyer les fichiers temporaires
            deleteDirectory(workDir.toFile());

            // Renvoyer le fichier pour le téléchargement
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=rapport_securite.txt")
                    .contentType(MediaType.TEXT_PLAIN)
                    .body(reportBytes);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
        }
    }

    private void deleteDirectory(File dir) {
        if (dir.isDirectory()) {
            for (File f : dir.listFiles()) deleteDirectory(f);
        }
        dir.delete();
    }
}