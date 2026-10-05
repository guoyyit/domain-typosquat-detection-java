package com.github.guoyyit.domaintyposquatdetectionjava.service;

import com.github.guoyyit.domaintyposquatdetectionjava.model.BlockAction;
import com.github.guoyyit.domaintyposquatdetectionjava.model.BlockEntry;
import com.github.guoyyit.domaintyposquatdetectionjava.model.BlockLifecycle;
import com.github.guoyyit.domaintyposquatdetectionjava.model.BlockStatus;
import com.github.guoyyit.domaintyposquatdetectionjava.model.BlockTransition;
import com.github.guoyyit.domaintyposquatdetectionjava.state.GuardState;
import com.github.guoyyit.domaintyposquatdetectionjava.state.StateData;
import org.springframework.stereotype.Service;

/**
 * 封禁生命周期：状态链的追加与查询。
 * 状态链只追加、不修改、不删除，与触发它的状态变更处于同一写事务，
 * 因此链上每条记录的变更前状态恒等于上一条记录的变更后状态（链式闭合）。
 */
@Service
public class BlockLifecycleService {

    private final GuardState state;

    public BlockLifecycleService(GuardState state) {
        this.state = state;
    }

    /**
     * 在已有写事务的 {@link StateData} 上追加一次状态变更，
     * 保证状态链与状态变更同一原子事务提交。
     */
    public BlockTransition recordTransition(StateData s, String domain, BlockAction action,
                                            String operator, long timestampMillis, String reason,
                                            BlockStatus newStatus) {
        BlockLifecycle current = s.blockLifecycles.get(domain);
        BlockStatus previous = current == null ? BlockStatus.NONE : current.currentStatus();
        BlockTransition transition = new BlockTransition(
                domain,
                action,
                operator == null || operator.isBlank() ? "system" : operator,
                timestampMillis,
                reason == null ? "" : reason,
                previous,
                newStatus);
        s.blockLifecycles.put(domain, current == null
                ? BlockLifecycle.firstBlock(transition)
                : current.withTransition(transition));
        return transition;
    }

    /**
     * 在已有读/写事务内判断域名是否曾被封禁（含已过期、已解封）。
     */
    public boolean wasEverBlocked(StateData s, String domain) {
        BlockLifecycle lifecycle = s.blockLifecycles.get(domain);
        return lifecycle != null && lifecycle.everBlocked();
    }

    /**
     * 在已有读/写事务内派生指定时刻的生命周期状态：
     * 存储状态为 ACTIVE 但封禁条目已到期时，对外呈现为 EXPIRED。
     */
    public BlockStatus statusOf(StateData s, String domain, long nowMillis) {
        BlockLifecycle lifecycle = s.blockLifecycles.get(domain);
        if (lifecycle == null) {
            return BlockStatus.NONE;
        }
        if (lifecycle.currentStatus() == BlockStatus.ACTIVE) {
            BlockEntry entry = s.blocklist.get(domain);
            if (entry == null || !entry.activeAt(nowMillis)) {
                return BlockStatus.EXPIRED;
            }
        }
        return lifecycle.currentStatus();
    }

    /**
     * 查询域名的完整生命周期；从未封禁时返回 {@code null}。
     */
    public BlockLifecycle lifecycleOf(String domain) {
        return state.read(s -> s.blockLifecycles.get(domain));
    }

    public boolean wasEverBlocked(String domain) {
        return state.read(s -> wasEverBlocked(s, domain));
    }

    public BlockStatus statusOf(String domain, long nowMillis) {
        return state.read(s -> statusOf(s, domain, nowMillis));
    }
}
