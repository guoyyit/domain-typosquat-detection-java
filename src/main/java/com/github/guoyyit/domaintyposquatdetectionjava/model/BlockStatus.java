package com.github.guoyyit.domaintyposquatdetectionjava.model;

/**
 * 域名封禁生命周期状态。
 * <ul>
 *     <li>{@link #BLOCKED}：当前处于生效封禁；</li>
 *     <li>{@link #EXPIRED}：封禁到期并被清理，当前不封禁但保留历史；</li>
 *     <li>{@link #UNBLOCKED}：人工解封（含白名单申诉解除），当前不封禁但保留历史。</li>
 * </ul>
 */
public enum BlockStatus {
    BLOCKED,
    EXPIRED,
    UNBLOCKED
}
