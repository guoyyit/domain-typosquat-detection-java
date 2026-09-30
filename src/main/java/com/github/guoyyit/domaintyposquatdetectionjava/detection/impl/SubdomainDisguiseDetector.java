package com.github.guoyyit.domaintyposquatdetectionjava.detection.impl;

import com.github.guoyyit.domaintyposquatdetectionjava.detection.DetectionContext;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.DomainLabels;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.FeatureDetector;
import com.github.guoyyit.domaintyposquatdetectionjava.model.FeatureType;
import com.github.guoyyit.domaintyposquatdetectionjava.model.HitFeature;
import com.github.guoyyit.domaintyposquatdetectionjava.model.ProtectedDomain;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Optional;

/**
 * 受保护品牌/域完整出现在子域标签位置（如 paypal.evil.com、
 * secure.paypal.evil.net），而注册主机（末两级）并非该品牌时命中。
 * 合法的品牌自有子域（如 secure.paypal.com）末两级等于受保护域，不命中。
 */
@Component
public class SubdomainDisguiseDetector implements FeatureDetector {

    @Override
    public Optional<HitFeature> detect(DetectionContext context) {
        var cfg = context.getProperties().getSubdomainDisguise();
        if (!cfg.isEnabled()) {
            return Optional.empty();
        }
        String[] candidateLabels = DomainLabels.labels(context.getNormalized());
        if (candidateLabels.length < 3) {
            return Optional.empty();
        }
        String candidateHost = lastTwoLabels(candidateLabels);

        for (ProtectedDomain protectedDomain : context.getProtectedDomains()) {
            String protectedHost = lastTwoLabels(
                    DomainLabels.labels(protectedDomain.getDomain()));
            if (candidateHost.equals(protectedHost)) {
                continue;
            }
            String brand = effectiveBrand(protectedDomain);
            for (int i = 0; i <= candidateLabels.length - 3; i++) {
                String label = candidateLabels[i];
                if (label.equals(brand) || label.equals(protectedHost)) {
                    return Optional.of(new HitFeature(
                            FeatureType.SUBDOMAIN_DISGUISE,
                            cfg.getWeight(),
                            "brand '" + label + "' appears in subdomain label[" + i
                                    + "] while registrable host is '" + candidateHost
                                    + "' vs " + protectedDomain.getDomain()));
                }
            }
        }
        return Optional.empty();
    }

    /** 末两级标签构成的注册主机后缀，如 evil.com。 */
    private String lastTwoLabels(String[] labels) {
        if (labels.length <= 2) {
            return String.join(".", labels);
        }
        return labels[labels.length - 2] + "." + labels[labels.length - 1];
    }

    private String effectiveBrand(ProtectedDomain protectedDomain) {
        if (protectedDomain.getBrand() != null && !protectedDomain.getBrand().isBlank()) {
            return protectedDomain.getBrand().toLowerCase(Locale.ROOT);
        }
        return DomainLabels.leftmost(protectedDomain.getDomain());
    }
}
