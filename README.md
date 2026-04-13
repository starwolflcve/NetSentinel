# NetSentinel
### Analyseur de logs réseau & détecteur d'intrusion

> Projet Java — Cybersécurité B1  
> Durée : 12 heures (3 × 4h) | Travail de groupe

---

## Table des matières

- [Présentation](#présentation)
- [Fonctionnalités](#fonctionnalités)
- [Structure du projet](#structure-du-projet)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Détecteurs de menaces](#détecteurs-de-menaces)
- [Rapport de sécurité](#rapport-de-sécurité)
- [Tests unitaires](#tests-unitaires)
- [Technologies utilisées](#technologies-utilisées)

---

## Présentation

**NetSentinel** est un outil d'analyse forensique de logs réseau développé en Java. Il simule le travail d'un analyste SOC (Security Operations Center) en parsant des fichiers de logs Apache/Nginx, en détectant des comportements suspects et en générant un rapport d'alertes de sécurité.

Le projet couvre les notions de détection d'intrusion (IDS), d'analyse de logs, et de contre-mesures défensives.

---

## Fonctionnalités

### Séance 1 — Parsing & Dashboard
- Parsing de logs au format **Apache Combined Log** via expressions régulières
- Indexation par IP (`HashMap`) et par timestamp (`TreeMap`)
- Dashboard textuel avec :
  - Nombre total de requêtes parsées
  - Top 10 des IPs les plus actives
  - Distribution des codes HTTP (200, 301, 401, 403, 404, 500…)
  - Top 10 des URLs les plus accédées
  - Top 5 des User-Agents

### Séance 2 — Détection de menaces
- **Brute-Force** : détection de tentatives de connexion répétées (401/403)
- **Injection SQL** : détection de patterns suspects dans les URLs
- **DDoS** : détection de volume anormal de requêtes par seconde
- **Scan de vulnérabilités** : détection d'outils et de chemins suspects

### Séance 3 — Rapport & contre-mesures
- **Corrélation d'alertes** : scoring multi-détecteur avec escalade de sévérité
- **Rapport de sécurité** : fichier `rapport_securite.txt` structuré
- **Règles de blocage** : génération de règles `iptables` et `.htaccess`
- **Whitelist** : liste blanche d'IPs pour éviter les faux positifs
- **Tests unitaires** : minimum 5 tests JUnit 5

---

## Structure du projet

```
netsentinel/
├── src/
│   ├── main/java/com/netsentinel/
│   │   ├── Main.java                        # Point d'entrée
│   │   ├── model/
│   │   │   ├── LogEntry.java                # Modèle d'une ligne de log
│   │   │   ├── Alert.java                   # Modèle d'une alerte
│   │   │   └── Severity.java                # Enum : LOW, MEDIUM, HIGH, CRITICAL
│   │   ├── parser/
│   │   │   └── LogParser.java               # Parsing regex des logs Apache
│   │   ├── dashboard/
│   │   │   └── Dashboard.java               # Affichage des statistiques
│   │   ├── detector/
│   │   │   ├── ThreatDetector.java          # Interface commune
│   │   │   ├── BruteForceDetector.java      # Détection brute-force
│   │   │   ├── SqlInjectionDetector.java    # Détection injection SQL
│   │   │   ├── DDoSDetector.java            # Détection DDoS
│   │   │   └── ScanDetector.java            # Détection scan de vulnérabilités
│   │   └── report/
│   │       └── ReportGenerator.java         # Génération du rapport
│   └── test/java/com/netsentinel/
│       └── NetSentinelTest.java             # Tests unitaires JUnit 5
├── logs/
│   ├── access_log_clean.txt                 # Logs normaux (~10 000 lignes)
│   └── access_log_attack.txt                # Logs avec attaques cachées
├── whitelist.txt                            # IPs en liste blanche
├── rapport_securite.txt                     # Rapport généré (output)
└── pom.xml
```

---

## Prérequis

- **Java** 17+ (OpenJDK recommandé)
- **Maven** 3.6+
- **VS Code** avec l'extension *Extension Pack for Java* (optionnel)

Vérifiez vos versions :
```bash
java -version
mvn -version
```

---

## Installation

**1. Cloner le dépôt :**
```bash
git clone https://github.com/votre-username/NetSentinel.git
cd NetSentinel/netsentinel
```

**2. Compiler le projet :**
```bash
mvn compile
```

**3. Placer les fichiers de logs** dans le dossier `logs/` à la racine du projet Maven.

---

## Utilisation

### Lancer l'analyse complète
```bash
mvn compile exec:java -Dexec.mainClass="com.netsentinel.Main"
```

### Lancer les tests unitaires
```bash
mvn test
```

### Nettoyer et recompiler
```bash
mvn clean compile
```

### Exemple de sortie du dashboard
```
========================================
        NETSENTINEL — DASHBOARD
========================================

Total de requêtes parsées : 10000

--- Top 10 IPs les plus actives ---
  172.16.5.13 → 51 requêtes
  172.16.7.12 → 50 requêtes
  ...

--- Distribution des codes HTTP ---
  HTTP 200 → 8510
  HTTP 404 →  293
  HTTP 500 →  201
  ...
```

---

## Détecteurs de menaces

### Brute-Force
Détecte les tentatives de connexion répétées depuis une même IP.
- **Seuil** : plus de 10 réponses 401/403 en moins de 5 minutes
- **Sévérité** : `MEDIUM` si > 10 tentatives, `HIGH` si > 50

### Injection SQL
Détecte les patterns suspects dans les URLs des requêtes.
- Patterns détectés : `' OR 1=1`, `UNION SELECT`, `--`, `DROP TABLE`, `xp_cmdshell`…
- Détection **case-insensitive**

### DDoS
Détecte un volume anormal de requêtes par seconde.
- **Seuil IP** : alerte si une IP dépasse 10× la moyenne sur 10 secondes
- **Seuil global** : `CRITICAL` si le volume global dépasse 50× la moyenne

### Scan de vulnérabilités
Détecte les outils et comportements de reconnaissance.
- **Chemins suspects** : `/admin`, `/wp-login.php`, `/.env`, `/phpmyadmin`, `/.git/config`…
- **User-agents malveillants** : `sqlmap`, `nikto`, `nmap`, `dirbuster`, `gobuster`
- **Scan de répertoires** : plus de 20 URLs différentes en 404 depuis une même IP

---

## Corrélation d'alertes

Le système de scoring combine les résultats de plusieurs détecteurs pour évaluer la dangerosité réelle d'une IP :

| Détecteurs déclenchés | Effet sur la sévérité |
|---|---|
| 1 détecteur | Sévérité inchangée |
| 2 détecteurs | +1 niveau (ex: `MEDIUM` → `HIGH`) |
| 3+ détecteurs | Automatiquement `CRITICAL` |

---

## Rapport de sécurité

Le fichier `rapport_securite.txt` est généré automatiquement et contient :

1. **Résumé exécutif** — nombre d'alertes par sévérité, IPs les plus dangereuses
2. **Timeline des incidents** — alertes classées chronologiquement
3. **Détail par IP suspecte** — toutes les alertes associées
4. **Recommandations** — actions suggérées par type de menace
5. **Règles de blocage** — règles `iptables` pour les IPs HIGH/CRITICAL

Exemple de règle générée :
```bash
iptables -A INPUT -s 203.0.113.50 -j DROP
```

---

## Tests unitaires

Les tests JUnit 5 couvrent :

| # | Test |
|---|---|
| 1 | Parsing correct d'une ligne de log Apache |
| 2 | Séquence de 15 requêtes 401 en 2 min → alerte brute-force |
| 3 | URL contenant `' OR 1=1` → alerte SQL injection |
| 4 | IP whitelistée → aucune alerte générée |
| 5 | Corrélation multi-détecteur → escalade de sévérité |

```bash
mvn test
```

---

## Technologies utilisées

| Technologie | Usage |
|---|---|
| Java 17+ | Langage principal |
| `java.util.regex` | Parsing des logs (Pattern, Matcher) |
| `java.time.LocalDateTime` | Gestion des timestamps |
| `HashMap`, `TreeMap` | Indexation des entrées |
| `BufferedReader`, `FileWriter` | Lecture/écriture de fichiers |
| JUnit 5 | Tests unitaires |
| Maven | Gestion des dépendances et build |

---

## Notions cybersécurité couvertes

- Analyse forensique de logs
- Détection d'intrusion (IDS) par signatures et anomalies
- Attaques web : brute-force, injection SQL, scan, DDoS
- Contre-mesures : `iptables`, `.htaccess`, whitelisting
- Posture défensive : rapport d'incident, évaluation des risques

---

## Ressources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Apache Log Format](https://httpd.apache.org/docs/current/logs.html)
- [Java Regex — Pattern](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/util/regex/Pattern.html)
- [SANS IDS FAQ](https://www.sans.org/)

---
