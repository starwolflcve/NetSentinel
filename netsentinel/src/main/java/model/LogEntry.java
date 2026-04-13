package model;

import java.time.LocalDateTime;

public class LogEntry {

    private String ip;
    private String user;
    private LocalDateTime timestamp;
    private String method;
    private String url;
    private String protocol;
    private int statusCode;
    private long responseSize;
    private String referer;
    private String userAgent;

    // Constructeur
    public LogEntry(String ip, String user, LocalDateTime timestamp,
                    String method, String url, String protocol,
                    int statusCode, long responseSize,
                    String referer, String userAgent) {
        this.ip = ip;
        this.user = user;
        this.timestamp = timestamp;
        this.method = method;
        this.url = url;
        this.protocol = protocol;
        this.statusCode = statusCode;
        this.responseSize = responseSize;
        this.referer = referer;
        this.userAgent = userAgent;
    }

    // Getters
    public String getIp() { return ip; }
    public String getUser() { return user; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public String getMethod() { return method; }
    public String getUrl() { return url; }
    public String getProtocol() { return protocol; }
    public int getStatusCode() { return statusCode; }
    public long getResponseSize() { return responseSize; }
    public String getReferer() { return referer; }
    public String getUserAgent() { return userAgent; }

    @Override
    public String toString() {
        return "[" + timestamp + "] " + ip + " " + method + " " + url + " " + statusCode;
    }
}