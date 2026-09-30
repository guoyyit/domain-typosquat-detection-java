package com.github.guoyyit.domaintyposquatdetectionjava.model;

import java.util.List;

/**
 * 单条域名的判定结果。判定结论始终反映风险本身；
 * 白名单只影响处置而不改变结论，历史/当前封禁状态单独标记。
 *
 * @param id                判定记录 id（用于历史查询）
 * @param input             原始输入
 * @param normalized        归一化后的 ASCII 域名
 * @param verdict           风险结论
 * @param totalScore        综合分数（0~maxScore）
 * @param hits              命中特征列表，按类型固定顺序排列
 * @param whitelisted       是否处于白名单（人工解除）状态
 * @param currentlyBanned   判定时是否在封禁有效期内
 * @param previouslyBanned  是否存在历史封禁（已过期或已人工解封）
 * @param timestamp         判定时间（epoch millis）
 */
public record DetectionResult(
        String id,
        String input,
        String normalized,
        Verdict verdict,
        int totalScore,
        List<HitFeature> hits,
        boolean whitelisted,
        boolean currentlyBanned,
        boolean previouslyBanned,
        long timestamp
) {
}
