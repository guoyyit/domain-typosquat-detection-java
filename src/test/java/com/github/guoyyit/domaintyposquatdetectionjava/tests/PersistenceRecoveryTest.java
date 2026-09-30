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
import com.github.guoyyit.domaintyposquatdetectionjava.model.BanRecord;
import com.github.guoyyit.domaintyposquatdetectionjava.model.DetectionResult;
import com.github.guoyyit.domaintyposquatdetectionjava.model.ProtectedDomain;
import com.github.guoyyit.domaintyposquatdetectionjava.model.Verdict;
import com.github.guoyyit.domaintyposquatdetectionjava.model.WhitelistEntry;
import com.github.guoyyit.domaintyposquatdetectionjava.service.DetectionService;
import com.github.guoyyit.domaintyposquatdetectionjava.service.EnforcementService;
import com.github.guoyyit.domaintyposquatdetectionjava.state.StateRepository;
import com.github.guoyyit.domaintyposquatdetectionjava.state.StateStore;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PersistenceRecoveryTest {

    private final DomainNormalizer normalizer = new DomainNormalizer();

    private List<FeatureDetector> detectors() {
        ConfusableMapper confusableMapper = new ConfusableMapper();
        return List.of(
                new EditDistanceDetector(),
                new InsertDeleteDetector(),
                new HomoglyphDetector(confusableMapper),
                new TldSwapDetector(),
                new BrandAffixDetector(),
                new SubdomainDisguiseDetector());
    }

    private StateRepository repository(Path dir) {
        DetectionProperties properties = new DetectionProperties();
        properties.getPersistence().setDir(dir.toString());
        StateRepository repository =
                new StateRepository(new StateStore(properties, new ObjectMapper()), normalizer);
        repository.init();
        return repository;
    }

    private DetectionService detectionService(StateRepository repository) {
        return new DetectionService(new DetectionProperties(), normalizer, detectors(), repository);
    }

    @Test
    void stateSurvivesRestartExactly() {
        Path dir = createTempDir();
        StateRepository first = repository(dir);
        ProtectedDomain protectedDomain =
                first.addProtectedDomain(normalizer.normalize("paypal.com"), "paypal");

        DetectionService detectionService = detectionService(first);
        DetectionResult beforeRemoval = detectionService.detect("paypai.com");

        EnforcementService enforcement =
                new EnforcementService(first, new DetectionProperties(), normalizer);
        enforcement.ban("paypai.com", "automatic", beforeRemoval.id(), null);
        enforcement.whitelist("mistake.com", "bob", "appeal ok");

        // 重启：新建 repository，从同一路径加载
        StateRepository restarted = repository(dir);
        List<ProtectedDomain> domains = restarted.snapshotProtectedDomains();
        assertEquals(1, domains.size());
        assertEquals(protectedDomain.getId(), domains.get(0).getId());
        assertEquals("paypal.com", domains.get(0).getDomain());

        List<BanRecord> bans = restarted.snapshotBans();
        assertEquals(1, bans.size());
        assertEquals(BanRecord.Status.ACTIVE, bans.get(0).getStatus());
        assertEquals("paypai.com", bans.get(0).getDomain());

        List<WhitelistEntry> whitelist = restarted.snapshotWhitelist();
        assertEquals(1, whitelist.size());
        assertEquals("bob", whitelist.get(0).getOperator());

        List<DetectionResult> history = restarted.snapshotHistory();
        assertEquals(1, history.size());
        assertEquals(beforeRemoval.id(), history.get(0).id());
        assertEquals(Verdict.SUSPICIOUS, history.get(0).verdict());
    }

    @Test
    void historyRemainsQueryableAfterDictionaryChange() {
        Path dir = createTempDir();
        StateRepository repository = repository(dir);
        DetectionService detectionService = detectionService(repository);

        repository.addProtectedDomain(normalizer.normalize("paypal.com"), "paypal");
        DetectionResult flagged = detectionService.detect("paypai.com");
        assertEquals(Verdict.SUSPICIOUS, flagged.verdict());

        String id = repository.snapshotProtectedDomains().get(0).getId();
        repository.deleteProtectedDomain(id);

        DetectionResult afterDeletion = detectionService.detect("paypai.com");
        assertEquals(Verdict.SAFE, afterDeletion.verdict());

        List<DetectionResult> history = repository.queryHistory("paypai.com");
        assertEquals(2, history.size());
        assertEquals(Verdict.SUSPICIOUS, history.get(0).verdict());
        assertEquals(Verdict.SAFE, history.get(1).verdict());
    }

    @Test
    void failedPersistenceLeavesPreviousCompleteState() throws Exception {
        Path dir = createTempDir();
        StateStore firstStore = storeFor(dir);
        StateRepository first = repositoryWithStore(firstStore);
        first.addProtectedDomain(normalizer.normalize("paypal.com"), "paypal");

        Path stateFile = dir.resolve("state.json");
        assertTrue(Files.exists(stateFile));

        // 模拟崩溃残留临时文件：新保存会创建唯一临时名，旧临时文件不影响正式状态
        Files.writeString(dir.resolve("state.json.99.1.tmp"), "{broken json");
        first.addProtectedDomain(normalizer.normalize("google.com"), "google");

        StateRepository restarted = repository(dir);
        assertEquals(2, restarted.snapshotProtectedDomains().size());
        assertFalse(restarted.snapshotProtectedDomains().isEmpty());
    }

    private Path createTempDir() {
        try {
            return Files.createTempDirectory("typosquat-recovery-");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private StateStore storeFor(Path dir) {
        DetectionProperties properties = new DetectionProperties();
        properties.getPersistence().setDir(dir.toString());
        return new StateStore(properties, new ObjectMapper());
    }

    private StateRepository repositoryWithStore(StateStore store) {
        StateRepository repository = new StateRepository(store, normalizer);
        repository.init();
        return repository;
    }
}
