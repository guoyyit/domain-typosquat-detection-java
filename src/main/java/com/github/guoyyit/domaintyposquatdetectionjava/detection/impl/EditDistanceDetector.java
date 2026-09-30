package com.github.guoyyit.domaintyposquatdetectionjava.detection.impl;

import com.github.guoyyit.domaintyposquatdetectionjava.detection.DetectionContext;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.DomainLabels;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.FeatureDetector;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.LevenshteinUtil;
import com.github.guoyyit.domaintyposquatdetectionjava.model.FeatureType;
import com.github.guoyyit.domaintyposquatdetectionjava.model.HitFeature;
import com.github.guoyyit.domaintyposquatdetectionjava.model.ProtectedDomain;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * 与任一受保护域名的可注册主体（品牌标签所在域）Levenshtein 距离
 * 不超过阈值时命中。
 */
@Component
public class EditDistanceDetector implements FeatureDetector {

    @Override
    public Optional<HitFeature> detect(DetectionContext context) {
        var cfg = context.getProperties().getEditDistance();
        if (!cfg.isEnabled()) {
            return Optional.empty();
        }
        String candidate = DomainLabels.registrable(context.getNormalized());
        String candidateTld = DomainLabels.tld(context.getNormalized());
        ProtectedDomain bestMatch = null;
        int bestDistance = Integer.MAX_VALUE;
        for (ProtectedDomain protectedDomain : context.getProtectedDomains()) {
            String protectedRegistrable = DomainLabels.registrable(protectedDomain.getDomain());
            String protectedTld = DomainLabels.tld(protectedDomain.getDomain());
            if (candidate.equals(protectedRegistrable) || !candidateTld.equals(protectedTld)) {
                continue;
            }
            int distance = LevenshteinUtil.distance(candidate, protectedRegistrable);
            if (distance <= cfg.getMaxDistance() && distance > 0 && distance < bestDistance) {
                bestDistance = distance;
                bestMatch = protectedDomain;
            }
        }
        if (bestMatch == null) {
            return Optional.empty();
        }
        return Optional.of(new HitFeature(
                FeatureType.EDIT_DISTANCE,
                cfg.getWeight(),
                "levenshtein=" + bestDistance + " vs " + bestMatch.getDomain()));
    }
}
