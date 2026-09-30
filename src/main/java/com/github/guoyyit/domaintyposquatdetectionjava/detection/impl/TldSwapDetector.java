package com.github.guoyyit.domaintyposquatdetectionjava.detection.impl;

import com.github.guoyyit.domaintyposquatdetectionjava.detection.DetectionContext;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.DomainLabels;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.FeatureDetector;
import com.github.guoyyit.domaintyposquatdetectionjava.model.FeatureType;
import com.github.guoyyit.domaintyposquatdetectionjava.model.HitFeature;
import com.github.guoyyit.domaintyposquatdetectionjava.model.ProtectedDomain;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * 主体标签与受保护域相同、仅顶级域不同时命中。
 */
@Component
public class TldSwapDetector implements FeatureDetector {

    @Override
    public Optional<HitFeature> detect(DetectionContext context) {
        var cfg = context.getProperties().getTldSwap();
        if (!cfg.isEnabled()) {
            return Optional.empty();
        }
        String normalized = context.getNormalized();
        String candidateLeftmost = DomainLabels.leftmost(normalized);
        String candidateTld = DomainLabels.tld(normalized);
        for (ProtectedDomain protectedDomain : context.getProtectedDomains()) {
            String protectedLeftmost = DomainLabels.leftmost(protectedDomain.getDomain());
            String protectedTld = DomainLabels.tld(protectedDomain.getDomain());
            if (candidateLeftmost.equals(protectedLeftmost)
                    && !candidateTld.equals(protectedTld)) {
                return Optional.of(new HitFeature(
                        FeatureType.TLD_SWAP,
                        cfg.getWeight(),
                        "same label '" + candidateLeftmost + "', tld ." + candidateTld
                                + " instead of ." + protectedTld
                                + " vs " + protectedDomain.getDomain()));
            }
        }
        return Optional.empty();
    }
}
