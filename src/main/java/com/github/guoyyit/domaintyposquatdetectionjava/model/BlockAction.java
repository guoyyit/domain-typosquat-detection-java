package com.github.guoyyit.domaintyposquatdetectionjava.model;

/**
 * 封禁状态链上的变更动作。
 */
public enum BlockAction {
    /** 首次封禁（变更前状态为 NONE）。 */
    BLOCK,
    /** 再次封禁（变更前状态为 ACTIVE/EXPIRED/UNBLOCKED）。 */
    REBLOCK,
    /** 过期清理。 */
    EXPIRE,
    /** 人工解封或白名单解除。 */
    UNBLOCK
}
