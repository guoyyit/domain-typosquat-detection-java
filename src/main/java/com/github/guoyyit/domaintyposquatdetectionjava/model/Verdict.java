package com.github.guoyyit.domaintyposquatdetectionjava.model;

import java.util.List;

/**
 * 单条域名判定结果。相同输入必然产生相同的命中特征与分数。
 */
public record Verdict(
        String input,
        String normalizedDomain,
        String matchedBrand,
        String matchedProtectedDomain,
        List<FeatureHit> hits,
        double score,
        RiskLevel riskLevel,
        boolean whitelisted,
        boolean previouslyBlocked,
        boolean blocked,
        long evaluatedAtMillis
) {
}
