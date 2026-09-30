package com.github.guoyyit.domaintyposquatdetectionjava.detection.impl;

import com.github.guoyyit.domaintyposquatdetectionjava.detection.DomainLabels;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.DetectionContext;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.FeatureDetector;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.LevenshteinUtil;
import com.github.guoyyit.domaintyposquatdetectionjava.model.FeatureType;
import com.github.guoyyit.domaintyposquatdetectionjava.model.HitFeature;
import com.github.guoyyit.domaintyposquatdetectionjava.model.ProtectedDomain;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * 仅通过少量字符插入/删除即可由受保护域主体得到时命中
 * （不允许替换，区别于编辑距离）。
 */
@Component
public class InsertDeleteDetector implements FeatureDetector {

    @Override
    public Optional<HitFeature> detect(DetectionContext context) {
        var cfg = context.getProperties().getInsertDelete();
        if (!cfg.isEnabled()) {
            return Optional.empty();
        }
        String candidate = DomainLabels.registrable(context.getNormalized());
        String candidateTld = DomainLabels.tld(context.getNormalized());
        ProtectedDomain bestMatch = null;
        int bestDiff = Integer.MAX_VALUE;
        for (ProtectedDomain protectedDomain : context.getProtectedDomains()) {
            String protectedRegistrable = DomainLabels.registrable(protectedDomain.getDomain());
            String protectedTld = DomainLabels.tld(protectedDomain.getDomain());
            if (candidate.equals(protectedRegistrable) || !candidateTld.equals(protectedTld)) {
                continue;
            }
            int diff = Math.abs(candidate.length() - protectedRegistrable.length());
            if (diff > 0 && diff <= cfg.getMaxDistance()
                    && diff < bestDiff
                    && LevenshteinUtil.insertDeleteWithin(candidate, protectedRegistrable,
                            cfg.getMaxDistance())) {
                bestDiff = diff;
                bestMatch = protectedDomain;
            }
        }
        if (bestMatch == null) {
            return Optional.empty();
        }
        return Optional.of(new HitFeature(
                FeatureType.INSERT_DELETE,
                cfg.getWeight(),
                "insertDeleteDelta=" + bestDiff + " vs " + bestMatch.getDomain()));
    }
}
