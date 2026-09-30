package com.github.guoyyit.domaintyposquatdetectionjava.model;

/**
 * 白名单（人工解除）条目。
 *
 * @param domain            归一化域名
 * @param operator          操作者
 * @param operatedAtMillis  操作时间
 * @param reason            操作理由
 * @param previouslyBlocked 加入白名单前是否曾被封禁
 */
public record WhitelistEntry(
        String domain,
        String operator,
        long operatedAtMillis,
        String reason,
        boolean previouslyBlocked
) {
}
