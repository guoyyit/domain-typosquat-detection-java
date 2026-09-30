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
import com.github.guoyyit.domaintyposquatdetectionjava.service.EnforcementService;
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

class WhitelistRiskTest {

    private DetectionService detectionService;
    private EnforcementService enforcement;
    private StateRepository repository;

    @BeforeEach
    void setUp(@TempDir Path tempDir) {
        DetectionProperties properties = new DetectionProperties();
        properties.getPersistence().setDir(tempDir.toString());
        DomainNormalizer normalizer = new DomainNormalizer();
        repository = new StateRepository(new StateStore(properties, new ObjectMapper()), normalizer);
        repository.init();
        repository.addProtectedDomain(normalizer.normalize("paypal.com"), "paypal");
        ConfusableMapper confusableMapper = new ConfusableMapper();
        List<FeatureDetector> detectors = List.of(
                new EditDistanceDetector(),
                new InsertDeleteDetector(),
                new HomoglyphDetector(confusableMapper),
                new TldSwapDetector(),
                new BrandAffixDetector(),
                new SubdomainDisguiseDetector());
        detectionService = new DetectionService(properties, normalizer, detectors, repository);
        enforcement = new EnforcementService(repository, properties, normalizer);
    }

    @Test
    void whitelistedDomainStillShowsRiskAndHistoryAfterLift() {
        // 子域伪装 75 分，达到 TYPOSQUATTING
        DetectionResult firstHit = detectionService.detect("paypal.evil.com");
        assertEquals(Verdict.TYPOSQUATTING, firstHit.verdict());

        enforcement.ban("paypal.evil.com", "auto", firstHit.id(), null);
        assertFalse(enforcement.isAllowed("paypal.evil.com"));

        // 申诉成功：白名单解除封禁，但风险判定不变
        enforcement.whitelist("paypal.evil.com", "carol", "verified legitimate partner");
        assertTrue(enforcement.isAllowed("paypal.evil.com"));

        DetectionResult recheck = detectionService.detect("paypal.evil.com");
        assertEquals(Verdict.TYPOSQUATTING, recheck.verdict());
        assertTrue(recheck.whitelisted());
        assertTrue(recheck.previouslyBanned());
        assertFalse(recheck.currentlyBanned());
        assertTrue(recheck.hits().stream()
                .anyMatch(h -> h.type() == FeatureType.SUBDOMAIN_DISGUISE));
    }
}
