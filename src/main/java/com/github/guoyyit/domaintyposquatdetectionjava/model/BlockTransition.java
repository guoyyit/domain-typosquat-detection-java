package com.github.guoyyit.domaintyposquatdetectionjava.model;

/**
 * 封禁状态链上的一次状态变更记录，追加式、不可变、永不删除。
 *
 * @param domain          归一化域名
 * @param action          变更动作
 * @param operator        操作者（自动处置为 system）
 * @param timestampMillis 操作时间
 * @param reason          操作原因
 * @param previousStatus  变更前状态
 * @param newStatus       变更后状态
 */
public record BlockTransition(
        String domain,
        BlockAction action,
        String operator,
        long timestampMillis,
        String reason,
        BlockStatus previousStatus,
        BlockStatus newStatus
) {
}
