package com.github.guoyyit.domaintyposquatdetectionjava.model;

import java.util.ArrayList;
import java.util.List;

/**
 * 单个域名的封禁生命周期：历史封禁标记 + 当前状态 + 完整状态链。
 * 条目一旦创建永不删除，因此「曾被封禁」在过期清理与解封后仍可追溯。
 *
 * @param domain       归一化域名
 * @param everBlocked  是否曾被封禁（生命周期存在即曾为真，显式冗余便于查询）
 * @param currentStatus 当前生命周期状态（读取时需结合封禁条目到期时间派生）
 * @param transitions  按时间顺序追加的完整状态链
 */
public record BlockLifecycle(
        String domain,
        boolean everBlocked,
        BlockStatus currentStatus,
        List<BlockTransition> transitions
) {

    /**
     * 追加一次状态变更，返回更新后的新生命周期（不可变更新）。
     */
    public BlockLifecycle withTransition(BlockTransition transition) {
        List<BlockTransition> next = new ArrayList<>(transitions);
        next.add(transition);
        return new BlockLifecycle(domain, true, transition.newStatus(), List.copyOf(next));
    }

    /**
     * 以首次封禁创建生命周期。
     */
    public static BlockLifecycle firstBlock(BlockTransition transition) {
        return new BlockLifecycle(transition.domain(), true, transition.newStatus(),
                List.of(transition));
    }
}
