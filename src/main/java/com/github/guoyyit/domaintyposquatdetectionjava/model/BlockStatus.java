package com.github.guoyyit.domaintyposquatdetectionjava.model;

/**
 * 域名封禁生命周期状态。
 */
public enum BlockStatus {
    /** 从未封禁（仅作为状态链中首次封禁的变更前状态出现）。 */
    NONE,
    /** 当前处于生效封禁中。 */
    ACTIVE,
    /** 封禁已到期（含已被过期清理）。 */
    EXPIRED,
    /** 已被人工解封或白名单解除。 */
    UNBLOCKED
}
