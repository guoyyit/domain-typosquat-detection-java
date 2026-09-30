package com.github.guoyyit.domaintyposquatdetectionjava.tests;

import com.github.guoyyit.domaintyposquatdetectionjava.model.BatchItemResult;
import com.github.guoyyit.domaintyposquatdetectionjava.model.ProtectedDomain;
import com.github.guoyyit.domaintyposquatdetectionjava.model.RiskLevel;
import com.github.guoyyit.domaintyposquatdetectionjava.model.Verdict;
import com.github.guoyyit.domaintyposquatdetectionjava.service.BatchDetectionService;
import com.github.guoyyit.domaintyposquatdetectionjava.service.BlocklistService;
import com.github.guoyyit.domaintyposquatdetectionjava.service.DetectionService;
import com.github.guoyyit.domaintyposquatdetectionjava.service.HistoryService;
import com.github.guoyyit.domaintyposquatdetectionjava.service.ProtectedDomainService;
import com.github.guoyyit.domaintyposquatdetectionjava.service.WhitelistService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
class GuardServiceIntegrationTest {

    @Autowired private DetectionService detectionService;
    @Autowired private BatchDetectionService batchDetectionService;
    @Autowired private ProtectedDomainService protectedDomainService;
    @Autowired private BlocklistService blocklistService;
    @Autowired private WhitelistService whitelistService;
    @Autowired private HistoryService historyService;

    @Test
    void detectionIsDeterministicAndExplainsHits() {
        ProtectedDomain brand = protectedDomainService.add("paypal", "paypal.com");
        assertNotNull(brand.id());

        Verdict first = detectionService.detect("https://PAYPAL-secure.com:443/");
        Verdict second = detectionService.detect("paypal-secure.com");
        assertEquals(second.hits(), first.hits());
        assertEquals(second.score(), first.score(), 0.0000001);
        assertFalse(first.hits().isEmpty());
        assertTrue(first.score() > 0);
        assertEquals("paypal-secure.com", first.normalizedDomain());
    }

    @Test
    void dictionaryChangeTakesEffectImmediatelyButHistoryRemains() {
        String raw = "g00gle-login.com";
        Verdict before = detectionService.detect(raw);
        int historyBefore = historyService.queryByDomain(before.normalizedDomain()).size();

        ProtectedDomain added = protectedDomainService.add("google", "google.com");
        Verdict after = detectionService.detect(raw);
        assertTrue(after.score() >= before.score());

        protectedDomainService.remove(added.id());
        Verdict afterRemoval = detectionService.detect(raw);
        assertEquals(0.0, afterRemoval.score(), 0.0000001);

        assertTrue(historyService.queryByDomain(before.normalizedDomain()).size() >= historyBefore);
    }

    @Test
    void batchIsolatesFailuresAndPreservesOrder() {
        protectedDomainService.add("amazon", "amazon.com");
        List<BatchItemResult> results = batchDetectionService.detectBatch(
                List.of("amazonn.com", "", "amazon-security.org", "notrelated.example"));

        assertEquals(4, results.size());
        assertEquals(0, results.get(0).index());
        assertEquals(1, results.get(1).index());
        assertEquals(2, results.get(2).index());
        assertEquals(3, results.get(3).index());
        assertNotNull(results.get(0).verdict());
        assertNull(results.get(1).verdict());
        assertNotNull(results.get(1).error());
        assertNotNull(results.get(2).verdict());
        assertNotNull(results.get(3).verdict());
    }

    @Test
    void batchRejectsOversizeRequests() {
        assertThrows(() -> batchDetectionService.detectBatch(List.of("a", "b", "c", "d", "e", "f")));
    }

    @Test
    void concurrentBlockAndQueryIsSafe() throws Exception {
        int threads = 8;
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            for (int t = 0; t < threads; t++) {
                final int idx = t;
                pool.submit(() -> {
                    start.await();
                    String domain = "race-" + idx + ".com";
                    blocklistService.block(domain, "test", 60_000L);
                    assertTrue(blocklistService.isBlocked(domain));
                    blocklistService.unblock(domain);
                    assertFalse(blocklistService.isBlocked(domain));
                    return null;
                });
            }
            start.countDown();
        } finally {
            pool.shutdown();
            assertTrue(pool.awaitTermination(20, TimeUnit.SECONDS));
        }
    }

    @Test
    void expiredEntriesAreReclaimedAndCanBeBlockedAgain() {
        long now = 1_000_000L;
        blocklistService.blockAt("temp-expired.com", "temporary", 100L, now);
        assertTrue(blocklistService.isBlockedAt("temp-expired.com", now + 50L));
        assertFalse(blocklistService.isBlockedAt("temp-expired.com", now + 200L));
        assertEquals(1, blocklistService.cleanupExpiredAt(now + 200L));

        blocklistService.blockAt("temp-expired.com", "re-offending", 100L, now + 300L);
        assertTrue(blocklistService.isBlockedAt("temp-expired.com", now + 350L));
    }

    @Test
    void whitelistKeepsRiskVisibleWithHistoricalBlock() {
        protectedDomainService.add("microsoft", "microsoft.com");
        long now = 5_000_000L;
        blocklistService.blockAt("micros0ft-login.com", "high risk", null, now);
        assertTrue(blocklistService.isBlockedAt("micros0ft-login.com", now));

        whitelistService.exemptAt("micros0ft-login.com", "analyst", "confirmed false positive", now);
        assertFalse(blocklistService.isBlockedAt("micros0ft-login.com", now + 10L));

        Verdict verdict = detectionService.detect("micros0ft-login.com", now + 10L);
        assertTrue(verdict.whitelisted());
        assertTrue(verdict.previouslyBlocked());
        assertFalse(verdict.blocked());
        assertTrue(verdict.score() > 0);
        assertEquals("analyst", whitelistService.list().stream()
                .filter(e -> e.domain().equals("micros0ft-login.com"))
                .findFirst().orElseThrow().operator());
    }

    private void assertThrows(Runnable runnable) {
        try {
            runnable.run();
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("expected IllegalArgumentException");
    }
}
