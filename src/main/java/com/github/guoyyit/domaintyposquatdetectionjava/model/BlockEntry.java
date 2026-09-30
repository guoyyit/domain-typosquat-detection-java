package com.github.guoyyit.domaintyposquatdetectionjava.model;

/**
 * 封禁条目。
 *
 * @param domain          归一化域名
 * @param reason          封禁原因
 * @param createdAtMillis 创建时间
 * @param expiresAtMillis 过期时间；{@code null} 表示永久封禁
 */
public record BlockEntry(
        String domain,
        String reason,
        long createdAtMillis,
        Long expiresAtMillis
) {

    public boolean activeAt(long nowMillis) {
        return expiresAtMillis == null || expiresAtMillis > nowMillis;
    }
}
