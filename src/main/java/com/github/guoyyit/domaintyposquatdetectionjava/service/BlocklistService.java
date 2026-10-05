package com.github.guoyyit.domaintyposquatdetectionjava.service;

import com.github.guoyyit.domaintyposquatdetectionjava.model.BlockAction;
import com.github.guoyyit.domaintyposquatdetectionjava.model.BlockEntry;
import com.github.guoyyit.domaintyposquatdetectionjava.model.BlockLifecycle;
import com.github.guoyyit.domaintyposquatdetectionjava.model.BlockStatus;
import com.github.guoyyit.domaintyposquatdetectionjava.state.GuardState;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * 封禁名单：并发安全的封禁、解封、过期清理与查询。
 * 每次状态变更在同一写事务内向状态链追加记录，历史封禁状态永不丢失。
 */
@Service
public class BlocklistService {

    private final GuardState state;
    private final BlockLifecycleService lifecycleService;

    public BlocklistService(GuardState state, BlockLifecycleService lifecycleService) {
        this.state = state;
        this.lifecycleService = lifecycleService;
    }

    public BlockEntry block(String domain, String reason, Long ttlMillis) {
        return block(domain, reason, ttlMillis, "system");
    }

    public BlockEntry block(String domain, String reason, Long ttlMillis, String operator) {
        return blockAt(domain, reason, ttlMillis, System.currentTimeMillis(), operator);
    }

    public BlockEntry blockAt(String domain, String reason, Long ttlMillis, long nowMillis) {
        return blockAt(domain, reason, ttlMillis, nowMillis, "system");
    }

    public BlockEntry blockAt(String domain, String reason, Long ttlMillis, long nowMillis,
                              String operator) {
        if (domain == null || domain.isBlank()) {
            throw new IllegalArgumentException("域名不能为空");
        }
        Long expiresAt = ttlMillis == null ? null : nowMillis + ttlMillis;
        BlockEntry entry = new BlockEntry(domain, reason == null ? "" : reason, nowMillis, expiresAt);
        return state.write(s -> {
            BlockAction action = s.blockLifecycles.containsKey(domain)
                    ? BlockAction.REBLOCK : BlockAction.BLOCK;
            s.blocklist.put(domain, entry);
            lifecycleService.recordTransition(s, domain, action, operator, nowMillis,
                    entry.reason(), BlockStatus.ACTIVE);
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
            for (String domain : expired) {
                s.blocklist.remove(domain);
                lifecycleService.recordTransition(s, domain, BlockAction.EXPIRE, "system",
                        nowMillis, "block expired", BlockStatus.EXPIRED);
            }
            return expired.size();
        });
    }

    public boolean unblock(String domain) {
        return unblock(domain, "system", "");
    }

    public boolean unblock(String domain, String operator, String reason) {
        return unblockAt(domain, operator, reason, System.currentTimeMillis());
    }

    public boolean unblockAt(String domain, String operator, String reason, long nowMillis) {
        return state.write(s -> {
            if (s.blocklist.remove(domain) == null) {
                return false;
            }
            lifecycleService.recordTransition(s, domain, BlockAction.UNBLOCK, operator,
                    nowMillis, reason, BlockStatus.UNBLOCKED);
            return true;
        });
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
        return state.read(s -> lifecycleService.wasEverBlocked(s, domain));
    }

    /**
     * 域名完整封禁生命周期（含状态链）；从未封禁返回 {@code null}。
     */
    public BlockLifecycle lifecycleOf(String domain) {
        return lifecycleService.lifecycleOf(domain);
    }

    /**
     * 指定时刻的派生生命周期状态（过期但未清理的生效封禁呈现为 EXPIRED）。
     */
    public BlockStatus statusOf(String domain, long nowMillis) {
        return lifecycleService.statusOf(domain, nowMillis);
    }

    public List<BlockEntry> list() {
        return state.read(s -> new ArrayList<>(s.blocklist.values()));
    }
}
