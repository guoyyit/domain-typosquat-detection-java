package com.github.guoyyit.domaintyposquatdetectionjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 检测与处置的全部可配置项，前缀 {@code domguard}。
 */
@ConfigurationProperties(prefix = "domguard")
public class DetectionProperties {

    private double editDistanceWeight = 0.40;
    private double insertDeleteWeight = 0.35;
    private double homoglyphWeight = 0.60;
    private double tldSwapWeight = 0.30;
    private double brandAffixWeight = 0.50;
    private double subdomainDisguiseWeight = 0.45;

    private int editDistanceThreshold = 2;
    private int insertDeleteThreshold = 1;
    private int homoglyphThreshold = 1;

    private double highScoreThreshold = 0.80;
    private double mediumScoreThreshold = 0.50;

    private int maxDomainLength = 253;
    private int maxBatchSize = 100;
    private int batchConcurrency = 8;
    private long perItemTimeoutMillis = 5000;

    private long blockTtlMillis = 7L * 24 * 60 * 60 * 1000;
    private boolean autoBlockEnabled = true;

    private int maxHistoryRecords = 10_000;
    private String dataDir = "./data";

    public double getEditDistanceWeight() { return editDistanceWeight; }
    public void setEditDistanceWeight(double v) { this.editDistanceWeight = v; }
    public double getInsertDeleteWeight() { return insertDeleteWeight; }
    public void setInsertDeleteWeight(double v) { this.insertDeleteWeight = v; }
    public double getHomoglyphWeight() { return homoglyphWeight; }
    public void setHomoglyphWeight(double v) { this.homoglyphWeight = v; }
    public double getTldSwapWeight() { return tldSwapWeight; }
    public void setTldSwapWeight(double v) { this.tldSwapWeight = v; }
    public double getBrandAffixWeight() { return brandAffixWeight; }
    public void setBrandAffixWeight(double v) { this.brandAffixWeight = v; }
    public double getSubdomainDisguiseWeight() { return subdomainDisguiseWeight; }
    public void setSubdomainDisguiseWeight(double v) { this.subdomainDisguiseWeight = v; }
    public int getEditDistanceThreshold() { return editDistanceThreshold; }
    public void setEditDistanceThreshold(int v) { this.editDistanceThreshold = v; }
    public int getInsertDeleteThreshold() { return insertDeleteThreshold; }
    public void setInsertDeleteThreshold(int v) { this.insertDeleteThreshold = v; }
    public int getHomoglyphThreshold() { return homoglyphThreshold; }
    public void setHomoglyphThreshold(int v) { this.homoglyphThreshold = v; }
    public double getHighScoreThreshold() { return highScoreThreshold; }
    public void setHighScoreThreshold(double v) { this.highScoreThreshold = v; }
    public double getMediumScoreThreshold() { return mediumScoreThreshold; }
    public void setMediumScoreThreshold(double v) { this.mediumScoreThreshold = v; }
    public int getMaxDomainLength() { return maxDomainLength; }
    public void setMaxDomainLength(int v) { this.maxDomainLength = v; }
    public int getMaxBatchSize() { return maxBatchSize; }
    public void setMaxBatchSize(int v) { this.maxBatchSize = v; }
    public int getBatchConcurrency() { return batchConcurrency; }
    public void setBatchConcurrency(int v) { this.batchConcurrency = v; }
    public long getPerItemTimeoutMillis() { return perItemTimeoutMillis; }
    public void setPerItemTimeoutMillis(long v) { this.perItemTimeoutMillis = v; }
    public long getBlockTtlMillis() { return blockTtlMillis; }
    public void setBlockTtlMillis(long v) { this.blockTtlMillis = v; }
    public boolean isAutoBlockEnabled() { return autoBlockEnabled; }
    public void setAutoBlockEnabled(boolean v) { this.autoBlockEnabled = v; }
    public int getMaxHistoryRecords() { return maxHistoryRecords; }
    public void setMaxHistoryRecords(int v) { this.maxHistoryRecords = v; }
    public String getDataDir() { return dataDir; }
    public void setDataDir(String v) { this.dataDir = v; }
}
