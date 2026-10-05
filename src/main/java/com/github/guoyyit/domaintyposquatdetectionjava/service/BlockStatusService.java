package com.github.guoyyit.domaintyposquatdetectionjava.service;

import com.github.guoyyit.domaintyposquatdetectionjava.model.StatusTransition;
import com.github.guoyyit.domaintyposquatdetectionjava.model.BlockEntry;
import com.github.guoyyit.domaintyposquatdetectionjava.model.BlockStatus;
import com.github.guoyyit.domaintyposquatdetectionjava.state.StateData;
import com.github.guoyyit.domaintyposquatdetectionjava.state.GuardState;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * 封禁状态链查询：历史封禁状态与完整状态转换记录在全部处置路径上可追溯。
 */
@Service
public class BlockStatusService {

    private final GuardState state;

    public BlockStatusService(GuardState state) {
        this.state = state;
    }

    /**
     * 该域名是否曾被封禁（无论当前是否已过期、解封或重新封禁）。
     */
    public boolean wasEverBlocked(String domain) {
        return state.read(s -> wasEverBlocked(s, domain));
    }

    /**
     * 查询某域名完整的封禁状态链，按操作时间先后排列。
     */
    public List<StatusTransition> chainOf(String domain) {
        return state.read(s -> chainOf(s, domain));
    }

    /**
     * 在调用方持有的事务（{@link StateData}）内判断是否曾被封禁。
     */
    boolean wasEverBlocked(StateData s, String domain) {
        List<StatusTransition> chain = s.blockStatusChain.get(domain);
        return chain != null && !chain.isEmpty();
    }

    /**
     * 在调用方持有的事务内查询状态链（不可变副本）。
     */
    List<StatusTransition> chainOf(StateData s, String domain) {
        List<StatusTransition> chain = s.blockStatusChain.get(domain);
        if (chain == null) {
            return List.of();
        }
        return List.copyOf(chain);
    }

    /**
     * 在调用方持有的事务内返回状态链末端状态；无记录返回 {@code null}（从未封禁）。
     */
    BlockStatus lastStatus(StateData s, String domain) {
        List<StatusTransition> chain = s.blockStatusChain.get(domain);
        if (chain == null || chain.isEmpty()) {
            return null;
        }
        return chain.get(chain.size() - 1).toStatus();
    }

    /**
     * 在调用方持有的事务内追加一次状态变更，状态链仅追加、永不覆盖。
     */
    StatusTransition appendTransition(StateData s, String domain, String action,
                                      BlockStatus fromStatus, BlockStatus toStatus,
                                      String operator, String reason, long timestampMillis) {
        StatusTransition transition = new StatusTransition(
                domain, action, fromStatus, toStatus,
                operator == null || operator.isBlank() ? "system" : operator,
                reason == null ? "" : reason, timestampMillis);
        s.blockStatusChain.computeIfAbsent(domain, key -> new ArrayList<>()).add(transition);
        return transition;
    }

    /**
     * 若当前封禁条目在 {@code nowMillis} 已到期但尚未登记 EXPIRED，则在状态链上补齐
     * BLOCKED -> EXPIRED 并从封禁名单移除；返回补登记前该域名是否曾被封禁。
     * 过期时间点取 TTL 到期时刻，保证不发生并发写时链上时间顺序正确。
     */
    boolean expireIfNeeded(StateData s, String domain, long nowMillis, String operator, String reason) {
        BlockEntry entry = s.blocklist.get(domain);
        if (entry == null) {
            return wasEverBlocked(s, domain);
        }
        if (entry.expiresAtMillis() != null && entry.expiresAtMillis() <= nowMillis) {
            appendTransition(s, domain, "EXPIRE", BlockStatus.BLOCKED, BlockStatus.EXPIRED,
                    operator, reason, entry.expiresAtMillis());
            s.blocklist.remove(domain);
        }
        return true;
    }

    /**
     * 仅用于恢复老版本快照：为尚无状态链、但封禁名单中存在的条目补一条初始 BLOCKED 记录，
     * 确保升级不丢失历史封禁状态。静态实现以避免与 {@link GuardState} 形成构造期循环依赖。
     */
    public static void backfillFromLegacySnapshot(StateData s) {
        for (BlockEntry entry : s.blocklist.values()) {
            java.util.List<StatusTransition> chain =
                    s.blockStatusChain.computeIfAbsent(entry.domain(), key -> new ArrayList<>());
            if (chain.isEmpty()) {
                chain.add(new StatusTransition(entry.domain(), "BLOCK", null, BlockStatus.BLOCKED,
                            "system", entry.reason(), entry.createdAtMillis()));
            }
        }
        for (var whitelisted : s.whitelist.entrySet()) {
            if (whitelisted.getValue().previouslyBlocked()) {
                java.util.List<StatusTransition> chain = s.blockStatusChain
                        .computeIfAbsent(whitelisted.getKey(), key -> new ArrayList<>());
                if (chain.isEmpty()) {
                    chain.add(new StatusTransition(whitelisted.getKey(), "BLOCK", null,
                            BlockStatus.BLOCKED, "system", "restored from legacy snapshot",
                            whitelisted.getValue().operatedAtMillis()));
                    chain.add(new StatusTransition(whitelisted.getKey(), "UNBLOCK",
                            BlockStatus.BLOCKED, BlockStatus.UNBLOCKED,
                            whitelisted.getValue().operator(), whitelisted.getValue().reason(),
                            whitelisted.getValue().operatedAtMillis()));
                }
            }
        }
    }
}
