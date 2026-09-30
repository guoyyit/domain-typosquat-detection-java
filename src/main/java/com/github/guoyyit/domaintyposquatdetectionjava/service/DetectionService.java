package com.github.guoyyit.domaintyposquatdetectionjava.service;

import com.github.guoyyit.domaintyposquatdetectionjava.config.DetectionProperties;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.DetectionContext;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.DomainNormalizer;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.FeatureDetector;
import com.github.guoyyit.domaintyposquatdetectionjava.model.BanRecord;
import com.github.guoyyit.domaintyposquatdetectionjava.model.DetectionResult;
import com.github.guoyyit.domaintyposquatdetectionjava.model.FeatureType;
import com.github.guoyyit.domaintyposquatdetectionjava.model.HitFeature;
import com.github.guoyyit.domaintyposquatdetectionjava.model.ProtectedDomain;
import com.github.guoyyit.domaintyposquatdetectionjava.model.Verdict;
import com.github.guoyyit.domaintyposquatdetectionjava.model.WhitelistEntry;
import com.github.guoyyit.domaintyposquatdetectionjava.state.StateRepository;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * 编排归一化、特征检测、评分与状态标记，产出确定性判定结果并记录历史。
 * 结果仅取决于输入和当时的受保护集合快照，相同输入必得相同命中与分数
 * （时间戳/记录 id 除外）。
 */
@Service
public class DetectionService {

    private final DetectionProperties properties;
    private final DomainNormalizer normalizer;
    private final List<FeatureDetector> detectors;
    private final StateRepository stateRepository;

    public DetectionService(DetectionProperties properties,
                            DomainNormalizer normalizer,
                            List<FeatureDetector> detectors,
                            StateRepository stateRepository) {
        this.properties = properties;
        this.normalizer = normalizer;
        this.detectors = detectors;
        this.stateRepository = stateRepository;
    }

    /**
     * 对单个输入执行检测并落历史。
     */
    public DetectionResult detect(String input) {
        String normalized = normalize(input);
        DetectionResult result = evaluate(input, normalized);
        stateRepository.appendHistory(result);
        return result;
    }

    /**
     * 仅做判定不落历史（批量服务可直接复用，历史仍由本方法统一落盘）。
     */
    public DetectionResult evaluate(String input, String normalized) {
        List<ProtectedDomain> protectedDomains = stateRepository.snapshotProtectedDomains();
        DetectionContext context = new DetectionContext(input, normalized, protectedDomains, properties);

        List<HitFeature> hits = new ArrayList<>();
        int total = 0;
        for (FeatureType type : FeatureType.values()) {
            Optional<HitFeature> hit = findHit(type, context);
            if (hit.isPresent()) {
                hits.add(hit.get());
                total += hit.get().score();
            }
        }
        int totalScore = Math.min(total, properties.getMaxScore());
        Verdict verdict = decide(totalScore);

        boolean whitelisted = isWhitelisted(normalized);
        BanStatus banStatus = currentBanStatus(normalized);

        return new DetectionResult(
                UUID.randomUUID().toString(),
                input,
                normalized,
                verdict,
                totalScore,
                List.copyOf(hits),
                whitelisted,
                banStatus.currentlyBanned(),
                banStatus.previouslyBanned(),
                Instant.now().toEpochMilli());
    }

    public String normalize(String input) {
        return normalizer.normalize(input);
    }

    private Optional<HitFeature> findHit(FeatureType type, DetectionContext context) {
        for (FeatureDetector detector : detectors) {
            Optional<HitFeature> hit = detector.detect(context);
            if (hit.isPresent() && hit.get().type() == type) {
                return hit;
            }
        }
        return Optional.empty();
    }

    private Verdict decide(int totalScore) {
        if (totalScore >= properties.getBlockThreshold()) {
            return Verdict.TYPOSQUATTING;
        }
        if (totalScore >= properties.getSuspiciousThreshold()) {
            return Verdict.SUSPICIOUS;
        }
        return Verdict.SAFE;
    }

    private boolean isWhitelisted(String normalizedDomain) {
        for (WhitelistEntry entry : stateRepository.snapshotWhitelist()) {
            if (entry.getDomain().equals(normalizedDomain)) {
                return true;
            }
        }
        return false;
    }

    private BanStatus currentBanStatus(String normalizedDomain) {
        long now = Instant.now().toEpochMilli();
        boolean current = false;
        boolean anyRecord = false;
        for (BanRecord ban : stateRepository.snapshotBans()) {
            if (!ban.getDomain().equals(normalizedDomain)) {
                continue;
            }
            anyRecord = true;
            if (ban.getStatus() == BanRecord.Status.ACTIVE && ban.getExpiresAt() > now) {
                current = true;
            }
        }
        return new BanStatus(current, !current && anyRecord);
    }

    private record BanStatus(boolean currentlyBanned, boolean previouslyBanned) {
    }
}
