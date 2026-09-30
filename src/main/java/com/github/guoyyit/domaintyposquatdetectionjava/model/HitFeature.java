package com.github.guoyyit.domaintyposquatdetectionjava.model;

/**
 * 单次判定中命中的一个特征及其得分。
 *
 * @param type      特征类型
 * @param score     该特征贡献的分数
 * @param detail    可复现的命中说明，如参照的受保护域名、编辑距离、命中位置等
 */
public record HitFeature(FeatureType type, int score, String detail) {
}
