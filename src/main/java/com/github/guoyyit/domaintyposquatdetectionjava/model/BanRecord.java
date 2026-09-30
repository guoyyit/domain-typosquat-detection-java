package com.github.guoyyit.domaintyposquatdetectionjava.model;

/**
 * 一条封禁记录。
 * ACTIVE 表示封禁生效中；EXPIRED 表示已过期（保留以便判定时标记历史状态，
 * 再次命中后可重新封禁为新记录）；LIFTED 表示被白名单人工解除。
 */
public class BanRecord {

    public enum Status { ACTIVE, EXPIRED, LIFTED }

    private String id;
    private String domain;
    private String reason;
    private String detectionId;
    private long bannedAt;
    private long expiresAt;
    private long updatedAt;
    private Status status;

    public BanRecord() {
    }

    public BanRecord(String id, String domain, String reason, String detectionId,
                     long bannedAt, long expiresAt, long updatedAt, Status status) {
        this.id = id;
        this.domain = domain;
        this.reason = reason;
        this.detectionId = detectionId;
        this.bannedAt = bannedAt;
        this.expiresAt = expiresAt;
        this.updatedAt = updatedAt;
        this.status = status;
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getDomain() { return domain; }
    public void setDomain(String domain) { this.domain = domain; }

    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }

    public String getDetectionId() { return detectionId; }
    public void setDetectionId(String detectionId) { this.detectionId = detectionId; }

    public long getBannedAt() { return bannedAt; }
    public void setBannedAt(long bannedAt) { this.bannedAt = bannedAt; }

    public long getExpiresAt() { return expiresAt; }
    public void setExpiresAt(long expiresAt) { this.expiresAt = expiresAt; }

    public long getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(long updatedAt) { this.updatedAt = updatedAt; }

    public Status getStatus() { return status; }
    public void setStatus(Status status) { this.status = status; }
}
