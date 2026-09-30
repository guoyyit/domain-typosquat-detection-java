package com.github.guoyyit.domaintyposquatdetectionjava.tests;

import com.github.guoyyit.domaintyposquatdetectionjava.config.DetectionProperties;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.ConfusableMapper;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.DomainNormalizer;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.FeatureDetector;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.impl.BrandAffixDetector;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.impl.EditDistanceDetector;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.impl.HomoglyphDetector;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.impl.InsertDeleteDetector;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.impl.SubdomainDisguiseDetector;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.impl.TldSwapDetector;
import com.github.guoyyit.domaintyposquatdetectionjava.model.DetectionResult;
import com.github.guoyyit.domaintyposquatdetectionjava.model.FeatureType;
import com.github.guoyyit.domaintyposquatdetectionjava.model.Verdict;
import com.github.guoyyit.domaintyposquatdetectionjava.service.DetectionService;
import com.github.guoyyit.domaintyposquatdetectionjava.state.StateRepository;
import com.github.guoyyit.domaintyposquatdetectionjava.state.StateStore;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DetectionFeatureTest {

    private DetectionService detectionService;
    private DomainNormalizer normalizer;

    @BeforeEach
    void setUp(@TempDir Path tempDir) {
        DetectionProperties properties = new DetectionProperties();
        properties.getPersistence().setDir(tempDir.toString());
        normalizer = new DomainNormalizer();
        ObjectMapper objectMapper = new ObjectMapper();
        StateStore stateStore = new StateStore(properties, objectMapper);
        StateRepository repository = new StateRepository(stateStore, normalizer);
        repository.init();
        repository.addProtectedDomain(normalizer.normalize("paypal.com"), "paypal");
        repository.addProtectedDomain(normalizer.normalize("google.com"), "google");

        ConfusableMapper confusableMapper = new ConfusableMapper();
        List<FeatureDetector> detectors = List.of(
                new EditDistanceDetector(),
                new InsertDeleteDetector(),
                new HomoglyphDetector(confusableMapper),
                new TldSwapDetector(),
                new BrandAffixDetector(),
                new SubdomainDisguiseDetector());
        detectionService = new DetectionService(properties, normalizer, detectors, repository);
    }

    private DetectionResult eval(String input) {
        String normalized = normalizer.normalize(input);
        return detectionService.evaluate(input, normalized);
    }

    private boolean hits(DetectionResult result, FeatureType type) {
        return result.hits().stream().anyMatch(h -> h.type() == type);
    }

    @Test
    void protectedDomainItselfIsSafe() {
        DetectionResult result = eval("https://PayPal.COM:443/");
        assertEquals(Verdict.SAFE, result.verdict());
        assertTrue(result.hits().isEmpty());
        assertEquals(0, result.totalScore());
    }

    @Test
    void editDistanceHitIsDeterministic() {
        DetectionResult first = eval("paypai.com");
        DetectionResult second = eval("PAYPAI.COM.");
        assertTrue(hits(first, FeatureType.EDIT_DISTANCE));
        assertEquals(first.totalScore(), second.totalScore());
        assertEquals(first.hits().size(), second.hits().size());
        assertEquals(first.verdict(), second.verdict());
    }

    @Test
    void insertDeleteHit() {
        DetectionResult result = eval("paypall.com");
        assertTrue(hits(result, FeatureType.INSERT_DELETE));
        assertTrue(result.totalScore() >= 30);
    }

    @Test
    void homoglyphHit() {
        DetectionResult result = eval("раypal.com");
        assertTrue(hits(result, FeatureType.HOMOGLYPH));
        assertEquals(Verdict.SUSPICIOUS, result.verdict());
    }

    @Test
    void tldSwapHit() {
        DetectionResult result = eval("paypal.org");
        assertTrue(hits(result, FeatureType.TLD_SWAP));
    }

    @Test
    void brandAffixHits() {
        assertTrue(hits(eval("paypal-secure.com"), FeatureType.BRAND_AFFIX));
        assertTrue(hits(eval("login-paypal.com"), FeatureType.BRAND_AFFIX));
        assertFalse(hits(eval("paypal.com"), FeatureType.BRAND_AFFIX));
    }

    @Test
    void subdomainDisguiseHits() {
        DetectionResult result = eval("paypal.evil.com");
        assertTrue(hits(result, FeatureType.SUBDOMAIN_DISGUISE));
        assertEquals(Verdict.TYPOSQUATTING, result.verdict());
    }

    @Test
    void unrelatedDomainIsSafe() {
        DetectionResult result = eval("example.org");
        assertEquals(Verdict.SAFE, result.verdict());
    }

    @Test
    void scoreIsCappedAndFeaturesExplained() {
        DetectionResult result = eval("paypal.evil.com");
        assertTrue(result.totalScore() <= 100);
        assertTrue(result.hits().stream().allMatch(h -> !h.detail().isBlank()));
    }
}
