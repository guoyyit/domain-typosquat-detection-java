package com.github.guoyyit.domaintyposquatdetectionjava.tests;

import com.github.guoyyit.domaintyposquatdetectionjava.config.DetectionProperties;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.EditDistance;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.FeatureDetector;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.HomoglyphMapper;
import com.github.guoyyit.domaintyposquatdetectionjava.model.FeatureHit;
import com.github.guoyyit.domaintyposquatdetectionjava.model.FeatureType;
import com.github.guoyyit.domaintyposquatdetectionjava.model.ProtectedDomain;
import com.github.guoyyit.domaintyposquatdetectionjava.normalize.DomainNormalizer;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FeatureDetectorTest {

    private final DomainNormalizer normalizer = new DomainNormalizer();
    private final FeatureDetector detector = new FeatureDetector(
            new DetectionProperties(), normalizer, new EditDistance(), new HomoglyphMapper());

    private final ProtectedDomain paypal = new ProtectedDomain("id-1", "paypal", "paypal.com");

    @Test
    void detectsEditDistance() {
        List<FeatureHit> hits = detector.detect("paypai.com", paypal);
        assertTrue(types(hits).contains(FeatureType.EDIT_DISTANCE));
    }

    @Test
    void detectsInsertionDeletionSeparately() {
        List<FeatureHit> hits = detector.detect("paypall.com", paypal);
        assertTrue(types(hits).contains(FeatureType.INSERT_DELETE), hits.toString());
    }

    @Test
    void detectsTldSwap() {
        List<FeatureHit> hits = detector.detect("paypal.org", paypal);
        assertTrue(types(hits).contains(FeatureType.TLD_SWAP), hits.toString());
    }

    @Test
    void detectsBrandAffix() {
        List<FeatureHit> hits = detector.detect("paypal-secure.com", paypal);
        assertTrue(types(hits).contains(FeatureType.BRAND_AFFIX), hits.toString());
    }

    @Test
    void detectsSubdomainDisguise() {
        List<FeatureHit> hits = detector.detect("paypal.evil.com", paypal);
        assertTrue(types(hits).contains(FeatureType.SUBDOMAIN_DISGUISE), hits.toString());
    }

    @Test
    void detectsHomoglyph() {
        String ascii = normalizer.normalize("раypal.com");
        String visual = normalizer.normalizeUnicode("раypal.com");
        List<FeatureHit> hits = detector.detect(ascii, visual, paypal);
        assertTrue(types(hits).contains(FeatureType.HOMOGLYPH), hits.toString());
    }

    @Test
    void sameInputProducesStableOrderedHits() {
        List<FeatureHit> first = detector.detect("paypal-secure.org", paypal);
        List<FeatureHit> second = detector.detect("paypal-secure.org", paypal);
        assertEquals(first, second);
        List<FeatureType> types = types(first);
        List<FeatureType> sorted = types.stream().sorted().toList();
        assertEquals(sorted, types);
    }

    private List<FeatureType> types(List<FeatureHit> hits) {
        return hits.stream().map(FeatureHit::feature).toList();
    }
}
