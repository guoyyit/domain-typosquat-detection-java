package com.github.guoyyit.domaintyposquatdetectionjava.service;

import com.github.guoyyit.domaintyposquatdetectionjava.config.DetectionProperties;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.FeatureDetector;
import com.github.guoyyit.domaintyposquatdetectionjava.model.BlockEntry;
import com.github.guoyyit.domaintyposquatdetectionjava.model.FeatureHit;
import com.github.guoyyit.domaintyposquatdetectionjava.model.ProtectedDomain;
import com.github.guoyyit.domaintyposquatdetectionjava.model.RiskLevel;
import com.github.guoyyit.domaintyposquatdetectionjava.model.Verdict;
import com.github.guoyyit.domaintyposquatdetectionjava.normalize.DomainNormalizer;
import com.github.guoyyit.domaintyposquatdetectionjava.state.GuardState;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * 单条域名的确定性检测、判定与处置联动。
 */
@Service
public class DetectionService {

    private final GuardState state;
    private final DetectionProperties properties;
    private final DomainNormalizer normalizer;
    private final FeatureDetector featureDetector;
    private final BlocklistService blocklistService;
    private final WhitelistService whitelistService;
    private final HistoryService historyService;

    public DetectionService(GuardState state,
                            DetectionProperties properties,
                            DomainNormalizer normalizer,
                            FeatureDetector featureDetector,
                            BlocklistService blocklistService,
                            WhitelistService whitelistService,
                            HistoryService historyService) {
        this.state = state;
        this.properties = properties;
        this.normalizer = normalizer;
        this.featureDetector = featureDetector;
        this.blocklistService = blocklistService;
        this.whitelistService = whitelistService;
        this.historyService = historyService;
    }

    public Verdict detect(String raw) {
        return detect(raw, System.currentTimeMillis());
    }

    public Verdict detect(String raw, long nowMillis) {
        String candidate = normalizer.normalize(raw);
        if (candidate == null || candidate.length() > properties.getMaxDomainLength()) {
            throw new IllegalArgumentException("非法或超长域名: " + raw);
        }
        final String normalized = candidate;
        final String visual = normalizer.normalizeUnicode(raw);

        DetectionOutcome outcome = state.read(s -> {
            List<FeatureHit> allHits = new ArrayList<>();
            ProtectedDomain best = null;
            double bestScore = -1d;
            for (ProtectedDomain protectedDomain : s.protectedDomains.values()) {
                List<FeatureHit> hits = featureDetector.detect(normalized, visual, protectedDomain);
                double score = sumScore(hits);
                if (score > bestScore || (score == bestScore && score > 0
                        && (best == null || protectedDomain.domain().compareTo(best.domain()) < 0))) {
                    bestScore = score;
                    best = protectedDomain;
                    allHits = hits;
                }
            }
            boolean whitelisted = s.whitelist.containsKey(normalized);
            boolean everBlocked = s.blocklist.containsKey(normalized)
                    || (s.whitelist.get(normalized) != null && s.whitelist.get(normalized).previouslyBlocked());
            BlockEntry currentBlock = s.blocklist.get(normalized);
            boolean currentlyBlocked = currentBlock != null && currentBlock.activeAt(nowMillis);
            return new DetectionOutcome(allHits, Math.max(0d, bestScore), best,
                    whitelisted, everBlocked, currentlyBlocked);
        });

        RiskLevel level = classify(outcome.score);
        boolean blocked = outcome.currentlyBlocked;

        if (!outcome.whitelisted && level == RiskLevel.HIGH
                && properties.isAutoBlockEnabled() && !outcome.currentlyBlocked) {
            blocklistService.blockAt(normalized, "auto:block high-risk detection",
                    properties.getBlockTtlMillis(), nowMillis);
            blocked = true;
        }

        Verdict verdict = new Verdict(
                raw,
                normalized,
                outcome.best == null ? null : outcome.best.brand(),
                outcome.best == null ? null : outcome.best.domain(),
                List.copyOf(outcome.hits),
                round(outcome.score),
                level,
                outcome.whitelisted,
                outcome.everBlocked,
                blocked,
                nowMillis);
        historyService.append(verdict);
        return verdict;
    }

    private double sumScore(List<FeatureHit> hits) {
        double total = 0d;
        for (FeatureHit hit : hits) {
            total += hit.score();
        }
        return total;
    }

    private RiskLevel classify(double score) {
        if (score >= properties.getHighScoreThreshold()) {
            return RiskLevel.HIGH;
        }
        if (score >= properties.getMediumScoreThreshold()) {
            return RiskLevel.MEDIUM;
        }
        return RiskLevel.LOW;
    }

    private double round(double value) {
        return Math.round(value * 1_000_000d) / 1_000_000d;
    }

    private record DetectionOutcome(
            List<FeatureHit> hits,
            double score,
            ProtectedDomain best,
            boolean whitelisted,
            boolean everBlocked,
            boolean currentlyBlocked) {
    }
}
