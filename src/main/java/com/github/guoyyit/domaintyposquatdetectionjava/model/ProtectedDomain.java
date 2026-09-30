package com.github.guoyyit.domaintyposquatdetectionjava.model;

/**
 * 受保护域名条目。brand 为用于前后缀拼接检测的品牌词，
 * 不指定时取归一化域名的最左标签。
 */
public class ProtectedDomain {

    private String id;
    private String domain;
    private String brand;
    private long createdAt;
    private long updatedAt;

    public ProtectedDomain() {
    }

    public ProtectedDomain(String id, String domain, String brand, long createdAt, long updatedAt) {
        this.id = id;
        this.domain = domain;
        this.brand = brand;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getDomain() { return domain; }
    public void setDomain(String domain) { this.domain = domain; }

    public String getBrand() { return brand; }
    public void setBrand(String brand) { this.brand = brand; }

    public long getCreatedAt() { return createdAt; }
    public void setCreatedAt(long createdAt) { this.createdAt = createdAt; }

    public long getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(long updatedAt) { this.updatedAt = updatedAt; }
}
