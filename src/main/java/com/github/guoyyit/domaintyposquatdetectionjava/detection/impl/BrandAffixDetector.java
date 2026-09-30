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
 * 最左注册标签以品牌词为子串且带额外前缀/后缀（如 paypal-secure、
 * login-paypal）时命中；品牌词整体独占标签不算命中（交子域伪装/TLD）。
 */
@Component
public class BrandAffixDetector implements FeatureDetector {

    @Override
    public Optional<HitFeature> detect(DetectionContext context) {
        var cfg = context.getProperties().getBrandAffix();
        if (!cfg.isEnabled()) {
            return Optional.empty();
        }
        String candidateLeftmost = DomainLabels.leftmost(context.getNormalized());
        for (ProtectedDomain protectedDomain : context.getProtectedDomains()) {
            String brand = effectiveBrand(protectedDomain);
            int index = candidateLeftmost.indexOf(brand);
            if (index < 0) {
                continue;
            }
            boolean prefixExtra = index > 0;
            boolean suffixExtra = index + brand.length() < candidateLeftmost.length();
            if (!prefixExtra && !suffixExtra) {
                continue;
            }
            String position = prefixExtra && suffixExtra ? "infix"
                    : prefixExtra ? "prefix" : "suffix";
            return Optional.of(new HitFeature(
                    FeatureType.BRAND_AFFIX,
                    cfg.getWeight(),
                    "brand '" + brand + "' appears as " + position + " of label '"
                            + candidateLeftmost + "' vs " + protectedDomain.getDomain()));
        }
        return Optional.empty();
    }

    private String effectiveBrand(ProtectedDomain protectedDomain) {
        if (protectedDomain.getBrand() != null && !protectedDomain.getBrand().isBlank()) {
            return protectedDomain.getBrand().toLowerCase(java.util.Locale.ROOT);
        }
        return DomainLabels.leftmost(protectedDomain.getDomain());
    }
}
