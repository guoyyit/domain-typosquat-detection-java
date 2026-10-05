package com.github.guoyyit.domaintyposquatdetectionjava.model;

/**
 * 封禁状态链上的单次状态变更。
 *
 * @param domain          归一化域名
 * @param action          变更动作（BLOCK / REBLOCK / EXPIRE / UNBLOCK）
 * @param fromStatus      变更前状态；首次封禁前为 {@code null}（从未封禁）
 * @param toStatus        变更后状态
 * @param operator        操作者（system 表示系统自动处置）
 * @param reason          操作原因
 * @param timestampMillis 操作时间
 */
public record StatusTransition(
        String domain,
        String action,
        BlockStatus fromStatus,
        BlockStatus toStatus,
        String operator,
        String reason,
        long timestampMillis
) {
}
