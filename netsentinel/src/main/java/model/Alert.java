package model;

import java.time.LocalDateTime;

public class Alert {
    private String type;
    private String description;
    private Severity severity;
    private String sourceIp;
    private LocalDateTime timestamp;
    private int count;
    
    public Alert(String type, String description, Severity severity, String sourceIp, LocalDateTime timestamp, int count) {
        this.type = type;
        this.description = description;
        this.severity = severity;
        this.sourceIp = sourceIp;
        this.timestamp = timestamp;
        this.count = count;
    }
    
    // Getters
    public String getType() { return type; }
    public String getDescription() { return description; }
    public Severity getSeverity() { return severity; }
    public String getSourceIp() { return sourceIp; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public int getCount() { return count; }
    
    @Override
    public String toString() {
        return String.format("[%s] %s - %s (IP: %s, Count: %d)", 
                severity, type, description, sourceIp, count);
    }
}
