package com.github.guoyyit.domaintyposquatdetectionjava.detection;

import com.github.guoyyit.domaintyposquatdetectionjava.config.DetectionProperties;
import com.github.guoyyit.domaintyposquatdetectionjava.model.FeatureType;
import com.github.guoyyit.domaintyposquatdetectionjava.model.FeatureHit;
import com.github.guoyyit.domaintyposquatdetectionjava.model.ProtectedDomain;
import com.github.guoyyit.domaintyposquatdetectionjava.normalize.DomainNormalizer;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * 针对单个受保护域名计算候选域名命中的全部特征。
 */
@Component
public class FeatureDetector {

    private final DetectionProperties properties;
    private final DomainNormalizer normalizer;
    private final EditDistance editDistance;
    private final HomoglyphMapper homoglyphMapper;

    public FeatureDetector(DetectionProperties properties,
                           DomainNormalizer normalizer,
                           EditDistance editDistance,
                           HomoglyphMapper homoglyphMapper) {
        this.properties = properties;
        this.normalizer = normalizer;
        this.editDistance = editDistance;
        this.homoglyphMapper = homoglyphMapper;
    }

    /**
     * @param candidate       已归一化的候选域名
     * @param protectedDomain 受保护域名
     * @return 命中特征列表（稳定排序）
     */
    public List<FeatureHit> detect(String candidate, ProtectedDomain protectedDomain) {
        return detect(candidate, candidate, protectedDomain);
    }

    /**
     * @param candidateAscii 已归一化的候选域名（ASCII / punycode）
     * @param candidateVisual 候选域名的 Unicode 视觉形式，用于同形字符比对
     */
    public List<FeatureHit> detect(String candidateAscii, String candidateVisual,
                                   ProtectedDomain protectedDomain) {
        List<FeatureHit> hits = new ArrayList<>();
        if (candidateAscii == null || protectedDomain == null || protectedDomain.domain() == null) {
            return hits;
        }
        String protectedHost = protectedDomain.domain();
        String candidateReg = normalizer.registrableDomain(candidateAscii);
        String protectedReg = normalizer.registrableDomain(protectedHost);

        if (candidateReg == null || protectedReg == null) {
            return hits;
        }
        String candLabel = stripTld(candidateReg);
        String protLabel = stripTld(protectedReg);
        String visualLabel = stripTld(normalizer.registrableDomain(candidateVisual));

        detectEditDistance(protectedHost, candLabel, visualLabel, protLabel, hits);
        detectTldSwap(protectedHost, candidateReg, protectedReg, candLabel, protLabel, hits);
        detectHomoglyph(protectedHost, visualLabel, protLabel, hits);
        detectBrandAffix(protectedHost, protectedDomain.brand(), visualLabel, protLabel, hits);
        detectSubdomainDisguise(protectedHost, candidateVisual, candLabel,
                protectedHost, protLabel, hits);

        hits.sort((x, y) -> x.feature().compareTo(y.feature()));
        return hits;
    }

    private void detectEditDistance(String protectedHost, String candLabel, String visualLabel,
                                    String protLabel, List<FeatureHit> hits) {
        int distance = editDistance.levenshtein(visualLabel, protLabel);
        if (distance == 0) {
            return;
        }
        if (homoglyphMapper.containsHomoglyph(visualLabel)) {
            return;
        }
        if (distance <= properties.getInsertDeleteThreshold()
                && editDistance.isInsertionOrDeletion(visualLabel, protLabel, distance)) {
            hits.add(hit(FeatureType.INSERT_DELETE, protectedHost,
                    properties.getInsertDeleteWeight(),
                    "label distance " + distance + " via insertion/deletion"));
        } else if (distance <= properties.getEditDistanceThreshold()) {
            hits.add(hit(FeatureType.EDIT_DISTANCE, protectedHost,
                    properties.getEditDistanceWeight(),
                    "label edit distance " + distance));
        }
    }

    private void detectTldSwap(String protectedHost, String candidateReg, String protectedReg,
                               String candLabel, String protLabel, List<FeatureHit> hits) {
        if (candLabel.equals(protLabel) && !candidateReg.equals(protectedReg)) {
            hits.add(hit(FeatureType.TLD_SWAP, protectedHost,
                    properties.getTldSwapWeight(),
                    "same label, tld " + tld(protectedReg) + " -> " + tld(candidateReg)));
        }
    }

    private void detectHomoglyph(String protectedHost, String candLabel, String protLabel, List<FeatureHit> hits) {
        String visual = candLabel;
        String skeleton = homoglyphMapper.skeleton(visual);
        int distance = editDistance.levenshtein(skeleton, protLabel);
        if (distance <= properties.getHomoglyphThreshold()
                && homoglyphMapper.containsHomoglyph(visual)
                && !visual.equals(protLabel)) {
            hits.add(hit(FeatureType.HOMOGLYPH, protectedHost,
                    properties.getHomoglyphWeight(),
                    "homoglyph skeleton distance " + distance));
        }
    }

    private void detectBrandAffix(String protectedHost, String brand,
                                  String visualLabel, String protLabel, List<FeatureHit> hits) {
        if (brand == null || brand.isEmpty()) {
            return;
        }
        String lowerBrand = brand.toLowerCase();
        String skeletonLabel = homoglyphMapper.skeleton(visualLabel);
        if ((visualLabel.contains(lowerBrand) || skeletonLabel.contains(lowerBrand))
                && !visualLabel.equals(protLabel)) {
            hits.add(hit(FeatureType.BRAND_AFFIX, protectedHost,
                    properties.getBrandAffixWeight(),
                    "label contains brand '" + lowerBrand + "' with prefix/suffix"));
        }
    }

    private void detectSubdomainDisguise(String protectedHost, String candidateVisual,
                                         String candLabel, String protectedHostName,
                                         String protLabel, List<FeatureHit> hits) {
        String[] labels = normalizer.labels(candidateVisual);
        if (labels.length <= 2) {
            return;
        }
        String[] protLabels = normalizer.labels(protectedHostName);
        String protectedHead = protLabels.length > 0 ? protLabels[0] : protLabel;
        boolean brandInSubLabel = false;
        for (int i = 0; i < labels.length - 2; i++) {
            String visualLabel = labels[i].toLowerCase(java.util.Locale.ROOT);
            if (visualLabel.equals(protectedHead) || visualLabel.contains(protectedHead)) {
                brandInSubLabel = true;
                break;
            }
        }
        if (brandInSubLabel) {
            hits.add(hit(FeatureType.SUBDOMAIN_DISGUISE, protectedHost,
                    properties.getSubdomainDisguiseWeight(),
                    "brand label appears in sub-domain of '" + candLabel + "'"));
        }
    }

    private FeatureHit hit(FeatureType type, String protectedDomain, double weight, String detail) {
        return new FeatureHit(type, protectedDomain, weight, weight, detail);
    }

    private String stripTld(String registrableDomain) {
        int dot = registrableDomain.lastIndexOf('.');
        return dot < 0 ? registrableDomain : registrableDomain.substring(0, dot);
    }

    private String tld(String registrableDomain) {
        int dot = registrableDomain.lastIndexOf('.');
        return dot < 0 ? "" : registrableDomain.substring(dot + 1);
    }
}
