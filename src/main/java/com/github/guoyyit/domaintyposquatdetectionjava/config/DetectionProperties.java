package com.github.guoyyit.domaintyposquatdetectionjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 域名仿冒检测的全部可调参数。
 * 各特征权重单位为分，综合分数为命中特征权重之和，上限 100。
 */
@ConfigurationProperties(prefix = "typosquat.detection")
public class DetectionProperties {

    private int suspiciousThreshold = 40;
    private int blockThreshold = 70;
    private int maxScore = 100;

    private EditDistance editDistance = new EditDistance();
    private InsertDelete insertDelete = new InsertDelete();
    private Homoglyph homoglyph = new Homoglyph();
    private TldSwap tldSwap = new TldSwap();
    private BrandAffix brandAffix = new BrandAffix();
    private SubdomainDisguise subdomainDisguise = new SubdomainDisguise();

    private Batch batch = new Batch();
    private Ban ban = new Ban();
    private Persistence persistence = new Persistence();

    public int getSuspiciousThreshold() { return suspiciousThreshold; }
    public void setSuspiciousThreshold(int suspiciousThreshold) { this.suspiciousThreshold = suspiciousThreshold; }

    public int getBlockThreshold() { return blockThreshold; }
    public void setBlockThreshold(int blockThreshold) { this.blockThreshold = blockThreshold; }

    public int getMaxScore() { return maxScore; }
    public void setMaxScore(int maxScore) { this.maxScore = maxScore; }

    public EditDistance getEditDistance() { return editDistance; }
    public void setEditDistance(EditDistance editDistance) { this.editDistance = editDistance; }

    public InsertDelete getInsertDelete() { return insertDelete; }
    public void setInsertDelete(InsertDelete insertDelete) { this.insertDelete = insertDelete; }

    public Homoglyph getHomoglyph() { return homoglyph; }
    public void setHomoglyph(Homoglyph homoglyph) { this.homoglyph = homoglyph; }

    public TldSwap getTldSwap() { return tldSwap; }
    public void setTldSwap(TldSwap tldSwap) { this.tldSwap = tldSwap; }

    public BrandAffix getBrandAffix() { return brandAffix; }
    public void setBrandAffix(BrandAffix brandAffix) { this.brandAffix = brandAffix; }

    public SubdomainDisguise getSubdomainDisguise() { return subdomainDisguise; }
    public void setSubdomainDisguise(SubdomainDisguise subdomainDisguise) { this.subdomainDisguise = subdomainDisguise; }

    public Batch getBatch() { return batch; }
    public void setBatch(Batch batch) { this.batch = batch; }

    public Ban getBan() { return ban; }
    public void setBan(Ban ban) { this.ban = ban; }

    public Persistence getPersistence() { return persistence; }
    public void setPersistence(Persistence persistence) { this.persistence = persistence; }

    public static class EditDistance {
        private boolean enabled = true;
        private int weight = 40;
        private int maxDistance = 2;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public int getWeight() { return weight; }
        public void setWeight(int weight) { this.weight = weight; }
        public int getMaxDistance() { return maxDistance; }
        public void setMaxDistance(int maxDistance) { this.maxDistance = maxDistance; }
    }

    public static class InsertDelete {
        private boolean enabled = true;
        private int weight = 30;
        private int maxDistance = 2;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public int getWeight() { return weight; }
        public void setWeight(int weight) { this.weight = weight; }
        public int getMaxDistance() { return maxDistance; }
        public void setMaxDistance(int maxDistance) { this.maxDistance = maxDistance; }
    }

    public static class Homoglyph {
        private boolean enabled = true;
        private int weight = 60;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public int getWeight() { return weight; }
        public void setWeight(int weight) { this.weight = weight; }
    }

    public static class TldSwap {
        private boolean enabled = true;
        private int weight = 25;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public int getWeight() { return weight; }
        public void setWeight(int weight) { this.weight = weight; }
    }

    public static class BrandAffix {
        private boolean enabled = true;
        private int weight = 70;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public int getWeight() { return weight; }
        public void setWeight(int weight) { this.weight = weight; }
    }

    public static class SubdomainDisguise {
        private boolean enabled = true;
        private int weight = 75;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public int getWeight() { return weight; }
        public void setWeight(int weight) { this.weight = weight; }
    }

    public static class Batch {
        private int maxBatchSize = 100;
        private int concurrency = 4;
        private long timeoutMillis = 5000;

        public int getMaxBatchSize() { return maxBatchSize; }
        public void setMaxBatchSize(int maxBatchSize) { this.maxBatchSize = maxBatchSize; }
        public int getConcurrency() { return concurrency; }
        public void setConcurrency(int concurrency) { this.concurrency = concurrency; }
        public long getTimeoutMillis() { return timeoutMillis; }
        public void setTimeoutMillis(long timeoutMillis) { this.timeoutMillis = timeoutMillis; }
    }

    public static class Ban {
        private long defaultTtlMillis = 24L * 60 * 60 * 1000;
        private long cleanupIntervalMillis = 60L * 1000;

        public long getDefaultTtlMillis() { return defaultTtlMillis; }
        public void setDefaultTtlMillis(long defaultTtlMillis) { this.defaultTtlMillis = defaultTtlMillis; }
        public long getCleanupIntervalMillis() { return cleanupIntervalMillis; }
        public void setCleanupIntervalMillis(long cleanupIntervalMillis) { this.cleanupIntervalMillis = cleanupIntervalMillis; }
    }

    public static class Persistence {
        private String dir = "data";

        public String getDir() { return dir; }
        public void setDir(String dir) { this.dir = dir; }
    }
}
