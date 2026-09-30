package com.github.guoyyit.domaintyposquatdetectionjava.model;

/**
 * 受保护品牌域名条目。
 *
 * @param id     稳定唯一标识
 * @param brand  品牌词
 * @param domain 归一化后的受保护域名
 */
public record ProtectedDomain(
        String id,
        String brand,
        String domain
) {
}
