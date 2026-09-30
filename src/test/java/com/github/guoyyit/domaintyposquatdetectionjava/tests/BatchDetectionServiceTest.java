package com.github.guoyyit.domaintyposquatdetectionjava.tests;

import com.github.guoyyit.domaintyposquatdetectionjava.config.DetectionProperties;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.DomainNormalizer;
import com.github.guoyyit.domaintyposquatdetectionjava.model.BatchItemResult;
import com.github.guoyyit.domaintyposquatdetectionjava.model.Verdict;
import com.github.guoyyit.domaintyposquatdetectionjava.service.BatchDetectionService;
import com.github.guoyyit.domaintyposquatdetectionjava.service.DetectionService;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.FeatureDetector;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.impl.BrandAffixDetector;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.impl.EditDistanceDetector;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.impl.HomoglyphDetector;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.impl.InsertDeleteDetector;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.impl.SubdomainDisguiseDetector;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.impl.TldSwapDetector;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.ConfusableMapper;
import com.github.guoyyit.domaintyposquatdetectionjava.state.StateRepository;
import com.github.guoyyit.domaintyposquatdetectionjava.state.StateStore;
import com.github.guoyyit.domaintyposquatdetectionjava.web.ApiException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BatchDetectionServiceTest {

    private BatchDetectionService batch;
    private DomainNormalizer normalizer;

    @BeforeEach
    void setUp(@TempDir Path tempDir) {
        DetectionProperties properties = new DetectionProperties();
        properties.getPersistence().setDir(tempDir.toString());
        properties.getBatch().setMaxBatchSize(5);
        properties.getBatch().setConcurrency(3);
        properties.getBatch().setTimeoutMillis(2000);
        normalizer = new DomainNormalizer();
        StateRepository repository = new StateRepository(
                new StateStore(properties, new ObjectMapper()), normalizer);
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
        DetectionService detectionService =
                new DetectionService(properties, normalizer, detectors, repository);
        batch = new BatchDetectionService(properties, detectionService);
    }

    @Test
    void resultsAlignOneToOneWithInputs() {
        List<String> inputs = List.of("paypai.com", "example.org", "paypal.com");
        List<BatchItemResult> results = batch.detectBatch(inputs);

        assertEquals(3, results.size());
        for (int i = 0; i < results.size(); i++) {
            assertEquals(i, results.get(i).index());
            assertEquals(inputs.get(i), results.get(i).input());
            assertNull(results.get(i).error());
        }
        assertEquals(Verdict.SUSPICIOUS, results.get(0).result().verdict());
        assertEquals(Verdict.SAFE, results.get(1).result().verdict());
        assertEquals(Verdict.SAFE, results.get(2).result().verdict());
    }

    @Test
    void singleInvalidItemIsIsolated() {
        List<String> inputs = List.of("paypai.com", "not a domain", "paypal-secure.com");
        List<BatchItemResult> results = batch.detectBatch(inputs);

        assertEquals(3, results.size());
        assertNull(results.get(0).error());
        assertNotNull(results.get(1).error());
        assertNull(results.get(1).result());
        assertNull(results.get(2).error());
        assertNotNull(results.get(2).result());
    }

    @Test
    void emptyBatchReturnsEmpty() {
        assertTrue(batch.detectBatch(List.of()).isEmpty());
    }

    @Test
    void oversizedBatchRejected() {
        List<String> tooMany = List.of("a.com", "b.com", "c.com", "d.com", "e.com", "f.com");
        ApiException ex = assertThrows(ApiException.class, () -> batch.detectBatch(tooMany));
        assertEquals(413, ex.getStatus());
    }
}
