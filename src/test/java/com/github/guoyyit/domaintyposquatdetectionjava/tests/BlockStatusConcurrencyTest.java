package com.github.guoyyit.domaintyposquatdetectionjava.tests;

import com.github.guoyyit.domaintyposquatdetectionjava.model.BlockStatus;
import com.github.guoyyit.domaintyposquatdetectionjava.model.StatusTransition;
import com.github.guoyyit.domaintyposquatdetectionjava.service.BlocklistService;
import com.github.guoyyit.domaintyposquatdetectionjava.service.DetectionService;
import com.github.guoyyit.domaintyposquatdetectionjava.service.ProtectedDomainService;
import com.github.guoyyit.domaintyposquatdetectionjava.service.WhitelistService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
class BlockStatusConcurrencyTest {

    @Autowired private BlocklistService blocklistService;
    @Autowired private WhitelistService whitelistService;
    @Autowired private DetectionService detectionService;
    @Autowired private ProtectedDomainService protectedDomainService;

    @Test
    void cleanupAndAppealInterleaveWithoutLosingHistory() throws Exception {
        protectedDomainService.add("microsoft", "microsoft.com");
        int domains = 40;
        for (int i = 0; i < domains; i++) {
            blocklistService.block("concurrent-" + i + ".com", "initial", 1L,
                    "ops", 8_000_000L);
        }

        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(4);
        try {
            for (int round = 0; round < 4; round++) {
                final long now = 8_001_000L + round * 100L;
                pool.submit(() -> awaitAndRun(start,
                        () -> blocklistService.cleanupExpiredAt(now, "system", "cleanup")));
                pool.submit(() -> awaitAndRun(start,
                        () -> whitelistService.exemptAt(domainPicked(0, domains),
                                "reviewer", "appeal", now)));
                pool.submit(() -> awaitAndRun(start,
                        () -> blocklistService.block(domainPicked(1, domains),
                                "re-block", 1L, "ops", now)));
                pool.submit(() -> awaitAndRun(start,
                        () -> blocklistService.unblock(domainPicked(2, domains),
                                "reviewer", "manual", now)));
            }
            start.countDown();
        } finally {
            pool.shutdown();
            assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        }

        for (int i = 0; i < domains; i++) {
            String domain = "concurrent-" + i + ".com";
            assertTrue(blocklistService.wasEverBlocked(domain),
                    "历史封禁状态丢失: " + domain);
            List<StatusTransition> chain = blocklistService.statusChain(domain);
            assertFalse(chain.isEmpty(), "状态链断裂: " + domain);
            assertChainContiguous(chain, domain);
            assertEquals(BlockStatus.BLOCKED, chain.get(0).toStatus());
        }
    }

    private String domainPicked(int offset, int domains) {
        int index = (int) (Thread.currentThread().getId() + offset) % domains;
        return "concurrent-" + index + ".com";
    }

    private void awaitAndRun(CountDownLatch start, Runnable runnable) {
        try {
            start.await();
            runnable.run();
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(ex);
        }
    }

    private void assertChainContiguous(java.util.List<StatusTransition> chain, String domain) {
        for (int i = 1; i < chain.size(); i++) {
            StatusTransition previous = chain.get(i - 1);
            StatusTransition current = chain.get(i);
            assertEquals(previous.toStatus(), current.fromStatus(),
                    "状态链前后不衔接: " + domain + " @ " + i);
        }
    }
}
