package com.github.guoyyit.domaintyposquatdetectionjava.model;

/**
 * 白名单（人工解除）条目。
 */
public class WhitelistEntry {

    private String id;
    private String domain;
    private String operator;
    private String reason;
    private long createdAt;

    public WhitelistEntry() {
    }

    public WhitelistEntry(String id, String domain, String operator, String reason, long createdAt) {
        this.id = id;
        this.domain = domain;
        this.operator = operator;
        this.reason = reason;
        this.createdAt = createdAt;
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getDomain() { return domain; }
    public void setDomain(String domain) { this.domain = domain; }

    public String getOperator() { return operator; }
    public void setOperator(String operator) { this.operator = operator; }

    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }

    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }
}
