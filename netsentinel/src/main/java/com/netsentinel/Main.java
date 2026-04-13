package com.netsentinel;
import dashboard.Dashboard;
import model.LogEntry;
import parser.LogParser;

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
    }
}