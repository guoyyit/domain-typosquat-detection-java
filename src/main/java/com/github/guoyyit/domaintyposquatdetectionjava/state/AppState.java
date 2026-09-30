package com.github.guoyyit.domaintyposquatdetectionjava.state;

import com.github.guoyyit.domaintyposquatdetectionjava.model.BanRecord;
import com.github.guoyyit.domaintyposquatdetectionjava.model.DetectionResult;
import com.github.guoyyit.domaintyposquatdetectionjava.model.ProtectedDomain;
import com.github.guoyyit.domaintyposquatdetectionjava.model.WhitelistEntry;

import java.util.ArrayList;
import java.util.List;

/**
 * 需要持久化的全部状态的聚合根。每次写盘整体序列化，
 * 配合临时文件 + 原子 rename 保证崩溃不留半成品。
 */
public class AppState {

    private long version;
    private long updatedAt;
    private List<ProtectedDomain> protectedDomains = new ArrayList<>();
    private List<BanRecord> bans = new ArrayList<>();
    private List<WhitelistEntry> whitelist = new ArrayList<>();
    private List<DetectionResult> history = new ArrayList<>();

    public long getVersion() { return version; }
    public void setVersion(long version) { this.version = version; }

    public long getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(long updatedAt) { this.updatedAt = updatedAt; }

    public List<ProtectedDomain> getProtectedDomains() { return protectedDomains; }
    public void setProtectedDomains(List<ProtectedDomain> protectedDomains) { this.protectedDomains = protectedDomains; }

    public List<BanRecord> getBans() { return bans; }
    public void setBans(List<BanRecord> bans) { this.bans = bans; }

    public List<WhitelistEntry> getWhitelist() { return whitelist; }
    public void setWhitelist(List<WhitelistEntry> whitelist) { this.whitelist = whitelist; }

    public List<DetectionResult> getHistory() { return history; }
    public void setHistory(List<DetectionResult> history) { this.history = history; }
}
