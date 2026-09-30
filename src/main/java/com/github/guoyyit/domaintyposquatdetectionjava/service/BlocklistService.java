package com.github.guoyyit.domaintyposquatdetectionjava.service;

import com.github.guoyyit.domaintyposquatdetectionjava.model.BlockEntry;
import com.github.guoyyit.domaintyposquatdetectionjava.state.GuardState;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * 封禁名单：并发安全的封禁、解封、过期清理与查询。
 */
@Service
public class BlocklistService {

    private final GuardState state;

    public BlocklistService(GuardState state) {
        this.state = state;
    }

    public BlockEntry block(String domain, String reason, Long ttlMillis) {
        return blockAt(domain, reason, ttlMillis, System.currentTimeMillis());
    }

    public BlockEntry blockAt(String domain, String reason, Long ttlMillis, long nowMillis) {
        if (domain == null || domain.isBlank()) {
            throw new IllegalArgumentException("域名不能为空");
        }
        Long expiresAt = ttlMillis == null ? null : nowMillis + ttlMillis;
        BlockEntry entry = new BlockEntry(domain, reason == null ? "" : reason, nowMillis, expiresAt);
        return state.write(s -> {
            s.blocklist.put(domain, entry);
            return entry;
        });
    }

    public int cleanupExpired() {
        return cleanupExpiredAt(System.currentTimeMillis());
    }

    public int cleanupExpiredAt(long nowMillis) {
        return state.write(s -> {
            List<String> expired = s.blocklist.entrySet().stream()
                    .filter(e -> e.getValue().expiresAtMillis() != null
                            && e.getValue().expiresAtMillis() <= nowMillis)
                    .map(e -> e.getKey())
                    .toList();
            expired.forEach(s.blocklist::remove);
            return expired.size();
        });
    }

    public boolean unblock(String domain) {
        return state.write(s -> s.blocklist.remove(domain) != null);
    }

    /**
     * 当前是否处于生效封禁（过期视为已解封并惰性清理）。
     */
    public boolean isBlocked(String domain) {
        return isBlockedAt(domain, System.currentTimeMillis());
    }

    public boolean isBlockedAt(String domain, long nowMillis) {
        return state.read(s -> {
            BlockEntry entry = s.blocklist.get(domain);
            return entry != null && (entry.expiresAtMillis() == null || entry.expiresAtMillis() > nowMillis);
        });
    }

    public boolean wasEverBlocked(String domain) {
        return state.read(s -> s.blocklist.containsKey(domain)
                || (s.whitelist.get(domain) != null && s.whitelist.get(domain).previouslyBlocked()));
    }

    public List<BlockEntry> list() {
        return state.read(s -> new ArrayList<>(s.blocklist.values()));
    }
}
