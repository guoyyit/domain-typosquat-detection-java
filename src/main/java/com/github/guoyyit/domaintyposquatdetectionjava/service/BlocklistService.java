package com.github.guoyyit.domaintyposquatdetectionjava.service;

import com.github.guoyyit.domaintyposquatdetectionjava.model.BlockEntry;
import com.github.guoyyit.domaintyposquatdetectionjava.model.BlockStatus;
import com.github.guoyyit.domaintyposquatdetectionjava.model.StatusTransition;
import com.github.guoyyit.domaintyposquatdetectionjava.state.StateData;
import com.github.guoyyit.domaintyposquatdetectionjava.state.GuardState;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 封禁名单：并发安全的封禁、解封、过期清理与查询。
 */
@Service
public class BlocklistService {

    private final GuardState state;
    private final AuditService auditService;
    private final BlockStatusService blockStatusService;

    public BlocklistService(GuardState state, AuditService auditService,
                            BlockStatusService blockStatusService) {
        this.state = state;
        this.auditService = auditService;
        this.blockStatusService = blockStatusService;
    }

    public BlockEntry block(String domain, String reason, Long ttlMillis) {
        return block(domain, reason, ttlMillis, "system", System.currentTimeMillis());
    }

    public BlockEntry blockAt(String domain, String reason, Long ttlMillis, long nowMillis) {
        return block(domain, reason, ttlMillis, "system", nowMillis);
    }

    public BlockEntry block(String domain, String reason, Long ttlMillis,
                            String operator, long nowMillis) {
        if (domain == null || domain.isBlank()) {
            throw new IllegalArgumentException("域名不能为空");
        }
        String normalizedReason = reason == null ? "" : reason;
        Long expiresAt = ttlMillis == null ? null : nowMillis + ttlMillis;
        return state.write(s -> {
            BlockStatus previous = blockStatusService.lastStatus(s, domain);
            if (previous == BlockStatus.BLOCKED) {
                BlockEntry active = s.blocklist.get(domain);
                if (active != null && active.expiresAtMillis() != null
                        && active.expiresAtMillis() <= nowMillis) {
                    previous = expireInTransaction(s, domain, active.expiresAtMillis(),
                            operator, "ttl expired before re-block");
                }
            }
            BlockEntry entry = new BlockEntry(domain, normalizedReason, nowMillis, expiresAt);
            s.blocklist.put(domain, entry);
            String action = previous == null ? "BLOCK" : "REBLOCK";
            blockStatusService.appendTransition(s, domain, action, previous, BlockStatus.BLOCKED,
                    operator, normalizedReason, nowMillis);
            auditService.appendInTransaction(s, action, domain, operator, normalizedReason);
            return entry;
        });
    }

    public int cleanupExpired() {
        return cleanupExpiredAt(System.currentTimeMillis());
    }

    public int cleanupExpiredAt(long nowMillis) {
        return cleanupExpiredAt(nowMillis, "system", "ttl expired cleanup");
    }

    public int cleanupExpiredAt(long nowMillis, String operator, String reason) {
        return state.write(s -> {
            List<String> candidates = s.blocklist.entrySet().stream()
                    .filter(e -> e.getValue().expiresAtMillis() != null
                            && e.getValue().expiresAtMillis() <= nowMillis)
                    .map(Map.Entry::getKey)
                    .toList();
            List<String> expired = new ArrayList<>();
            for (String domain : candidates) {
                BlockEntry entry = s.blocklist.get(domain);
                if (entry == null) {
                    continue;
                }
                if (entry.expiresAtMillis() != null && entry.expiresAtMillis() <= nowMillis) {
                    expireInTransaction(s, domain, entry.expiresAtMillis(),
                            operator, reason);
                    expired.add(domain);
                }
            }
            return expired.size();
        });
    }

    public boolean unblock(String domain) {
        return unblock(domain, "system", null, System.currentTimeMillis());
    }

    public boolean unblock(String domain, String operator, String reason, long nowMillis) {
        return state.write(s -> unblockInTransaction(s, domain, operator, reason, nowMillis));
    }

    /**
     * 在调用方持有的写事务内人工解封并追加状态链；白名单申诉复用此路径。
     * 返回该域名解封前是否曾被封禁。
     */
    boolean unblockInTransaction(StateData s, String domain, String operator,
                                 String reason, long nowMillis) {
        boolean everBlocked = blockStatusService.expireIfNeeded(s, domain, nowMillis,
                operator, "ttl expired before unblock");
        BlockEntry entry = s.blocklist.remove(domain);
        if (entry != null) {
            everBlocked = true;
            blockStatusService.appendTransition(s, domain, "UNBLOCK",
                    BlockStatus.BLOCKED, BlockStatus.UNBLOCKED,
                    operator, reason, nowMillis);
            auditService.appendInTransaction(s, "UNBLOCK", domain, operator, reason);
        }
        return everBlocked;
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
        return blockStatusService.wasEverBlocked(domain);
    }

    public List<StatusTransition> statusChain(String domain) {
        return blockStatusService.chainOf(domain);
    }

    public List<BlockEntry> list() {
        return state.read(s -> new ArrayList<>(s.blocklist.values()));
    }

    private BlockStatus expireInTransaction(StateData s, String domain, long expiredAtMillis,
                                            String operator, String reason) {
        s.blocklist.remove(domain);
        blockStatusService.appendTransition(s, domain, "EXPIRE",
                BlockStatus.BLOCKED, BlockStatus.EXPIRED, operator, reason, expiredAtMillis);
        auditService.appendInTransaction(s, "EXPIRE", domain, operator, reason);
        return BlockStatus.EXPIRED;
    }
}
