package com.github.guoyyit.domaintyposquatdetectionjava.model;

/**
 * 单次特征命中。
 *
 * @param feature         命中的特征类型
 * @param protectedDomain 命中的受保护域名（归一化形式）
 * @param weight          该特征配置权重
 * @param score           该特征对综合分数的贡献
 * @param detail          确定性的命中说明
 */
public record FeatureHit(
        FeatureType feature,
        String protectedDomain,
        double weight,
        double score,
        String detail
) {
}
