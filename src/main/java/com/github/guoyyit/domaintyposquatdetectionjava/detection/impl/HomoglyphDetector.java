package com.github.guoyyit.domaintyposquatdetectionjava.detection.impl;

import com.github.guoyyit.domaintyposquatdetectionjava.detection.DetectionContext;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.DomainLabels;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.ConfusableMapper;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.FeatureDetector;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.LevenshteinUtil;
import com.github.guoyyit.domaintyposquatdetectionjava.model.FeatureType;
import com.github.guoyyit.domaintyposquatdetectionjava.model.HitFeature;
import com.github.guoyyit.domaintyposquatdetectionjava.model.ProtectedDomain;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * 归一化后含同形字符（punycode 标签），且 ASCII 骨架与某受保护域主体
 * 相同或仅 1 个编辑距离时命中。
 */
@Component
public class HomoglyphDetector implements FeatureDetector {

    private final ConfusableMapper confusableMapper;

    public HomoglyphDetector(ConfusableMapper confusableMapper) {
        this.confusableMapper = confusableMapper;
    }

    @Override
    public Optional<HitFeature> detect(DetectionContext context) {
        var cfg = context.getProperties().getHomoglyph();
        if (!cfg.isEnabled() || !confusableMapper.containsHomoglyph(context.getNormalized())) {
            return Optional.empty();
        }
        String candidateRegistrable = confusableMapper.skeleton(
                DomainLabels.registrable(context.getNormalized()));
        String candidateTld = DomainLabels.tld(context.getNormalized());
        for (ProtectedDomain protectedDomain : context.getProtectedDomains()) {
            String protectedTld = DomainLabels.tld(protectedDomain.getDomain());
            if (!candidateTld.equals(protectedTld)) {
                continue;
            }
            String protectedRegistrable = confusableMapper.skeleton(
                    DomainLabels.registrable(protectedDomain.getDomain()));
            if (candidateRegistrable.equals(protectedRegistrable)
                    || LevenshteinUtil.distance(candidateRegistrable, protectedRegistrable) <= 1) {
                return Optional.of(new HitFeature(
                        FeatureType.HOMOGLYPH,
                        cfg.getWeight(),
                        "skeleton '" + candidateRegistrable + "' vs " + protectedDomain.getDomain()));
            }
        }
        return Optional.empty();
    }
}
