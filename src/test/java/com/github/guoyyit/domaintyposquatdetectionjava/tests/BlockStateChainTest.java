package com.github.guoyyit.domaintyposquatdetectionjava.tests;

import com.github.guoyyit.domaintyposquatdetectionjava.config.DetectionProperties;
import com.github.guoyyit.domaintyposquatdetectionjava.model.BlockAction;
import com.github.guoyyit.domaintyposquatdetectionjava.model.BlockLifecycle;
import com.github.guoyyit.domaintyposquatdetectionjava.model.BlockStatus;
import com.github.guoyyit.domaintyposquatdetectionjava.model.BlockTransition;
import com.github.guoyyit.domaintyposquatdetectionjava.model.Verdict;
import com.github.guoyyit.domaintyposquatdetectionjava.model.WhitelistEntry;
import com.github.guoyyit.domaintyposquatdetectionjava.service.BlocklistService;
import com.github.guoyyit.domaintyposquatdetectionjava.service.DetectionService;
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
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 封禁状态链：过期清理 / 人工解封后历史封禁状态保留，重复封禁链完整，并发交错不断链。
 */
@SpringBootTest
class BlockStateChainTest {

    @Autowired private DetectionService detectionService;
    @Autowired private ProtectedDomainService protectedDomainService;
    @Autowired private BlocklistService blocklistService;
    @Autowired private WhitelistService whitelistService;
    @Autowired private DetectionProperties properties;

    @Test
    void cleanupThenDetectRetainsHistoryAndReblocks() {
        protectedDomainService.add("stripe", "stripe.com");
        long t0 = 10_000_000L;
        Verdict first = detectionService.detect("strip3.com", t0);
        assertTrue(first.blocked());
        assertFalse(first.previouslyBlocked());

        long expiredAt = t0 + properties.getBlockTtlMillis() + 1000L;
        assertTrue(blocklistService.cleanupExpiredAt(expiredAt) >= 1);
        assertFalse(blocklistService.isBlockedAt("strip3.com", expiredAt));
        assertTrue(blocklistService.wasEverBlocked("strip3.com"));
        assertEquals(BlockStatus.EXPIRED, blocklistService.statusOf("strip3.com", expiredAt));

        Verdict second = detectionService.detect("strip3.com", expiredAt + 1000L);
        assertTrue(second.previouslyBlocked());
        assertTrue(second.blocked());

        BlockLifecycle lifecycle = blocklistService.lifecycleOf("strip3.com");
        assertEquals(List.of(BlockAction.BLOCK, BlockAction.EXPIRE, BlockAction.REBLOCK),
                actions(lifecycle));
        assertChainLinked(lifecycle);
    }

    @Test
    void cleanupThenAppealRetainsHistory() {
        protectedDomainService.add("shopify", "shopify.com");
        long t0 = 20_000_000L;
        Verdict first = detectionService.detect("sh0pify.com", t0);
        assertTrue(first.blocked());

        long expiredAt = t0 + properties.getBlockTtlMillis() + 1000L;
        assertTrue(blocklistService.cleanupExpiredAt(expiredAt) >= 1);

        WhitelistEntry entry = whitelistService.exemptAt(
                "sh0pify.com", "analyst", "false positive", expiredAt + 1000L);
        assertTrue(entry.previouslyBlocked());

        Verdict verdict = detectionService.detect("sh0pify.com", expiredAt + 2000L);
        assertTrue(verdict.whitelisted());
        assertTrue(verdict.previouslyBlocked());
        assertFalse(verdict.blocked());

        BlockLifecycle lifecycle = blocklistService.lifecycleOf("sh0pify.com");
        assertEquals(List.of(BlockAction.BLOCK, BlockAction.EXPIRE), actions(lifecycle));
        assertChainLinked(lifecycle);
    }

    @Test
    void unblockThenAppealRetainsHistory() {
        protectedDomainService.add("spotify", "spotify.com");
        long t0 = 30_000_000L;
        assertTrue(detectionService.detect("sp0tify.com", t0).blocked());

        assertTrue(blocklistService.unblockAt("sp0tify.com", "ops-lead", "manual review", t0 + 1000L));
        assertFalse(blocklistService.isBlockedAt("sp0tify.com", t0 + 1000L));
        assertTrue(blocklistService.wasEverBlocked("sp0tify.com"));

        WhitelistEntry entry = whitelistService.exemptAt("sp0tify.com", "analyst", "appeal", t0 + 2000L);
        assertTrue(entry.previouslyBlocked());

        Verdict verdict = detectionService.detect("sp0tify.com", t0 + 3000L);
        assertTrue(verdict.previouslyBlocked());

        BlockLifecycle lifecycle = blocklistService.lifecycleOf("sp0tify.com");
        assertEquals(List.of(BlockAction.BLOCK, BlockAction.UNBLOCK), actions(lifecycle));
        assertChainLinked(lifecycle);
        BlockTransition unblock = lifecycle.transitions().get(1);
        assertEquals("ops-lead", unblock.operator());
        assertEquals("manual review", unblock.reason());
        assertEquals(t0 + 1000L, unblock.timestampMillis());
        assertEquals(BlockStatus.ACTIVE, unblock.previousStatus());
        assertEquals(BlockStatus.UNBLOCKED, unblock.newStatus());
    }

    @Test
    void repeatedBlockChainIsCompleteAndOrdered() {
        String domain = "repeat-offender.example";
        long t = 40_000_000L;
        blocklistService.blockAt(domain, "first fraud", 1000L, t, "system");
        blocklistService.unblockAt(domain, "ops-a", "appeal accepted", t + 10L);
        blocklistService.blockAt(domain, "second fraud", 1000L, t + 20L, "analyst-b");
        assertTrue(blocklistService.cleanupExpiredAt(t + 2000L) >= 1);
        blocklistService.blockAt(domain, "third fraud", null, t + 3000L, "analyst-c");

        BlockLifecycle lifecycle = blocklistService.lifecycleOf(domain);
        assertNotNull(lifecycle);
        assertEquals(List.of(BlockAction.BLOCK, BlockAction.UNBLOCK, BlockAction.REBLOCK,
                BlockAction.EXPIRE, BlockAction.REBLOCK), actions(lifecycle));
        assertChainLinked(lifecycle);

        List<BlockTransition> chain = lifecycle.transitions();
        assertEquals("ops-a", chain.get(1).operator());
        assertEquals("appeal accepted", chain.get(1).reason());
        assertEquals("analyst-b", chain.get(2).operator());
        assertEquals("second fraud", chain.get(2).reason());
        assertEquals("system", chain.get(3).operator());
        assertEquals("analyst-c", chain.get(4).operator());
        assertEquals(BlockStatus.EXPIRED, chain.get(4).previousStatus());
        assertEquals(BlockStatus.ACTIVE, lifecycle.currentStatus());
        assertTrue(blocklistService.isBlockedAt(domain, t + 4000L));
    }

    @Test
    void concurrentCleanupAndAppealNeverLosesHistory() throws Exception {
        int iterations = 16;
        ExecutorService pool = Executors.newFixedThreadPool(4);
        try {
            for (int i = 0; i < iterations; i++) {
                String domain = "cleanup-exempt-race-" + i + ".example";
                long t0 = 50_000_000L + i * 1000L;
                blocklistService.blockAt(domain, "fraud", 50L, t0, "system");

                CountDownLatch start = new CountDownLatch(1);
                String raceDomain = domain;
                var cleanup = pool.submit(() -> {
                    await(start);
                    blocklistService.cleanupExpiredAt(t0 + 100L);
                    return null;
                });
                var appeal = pool.submit(() -> {
                    await(start);
                    whitelistService.exemptAt(raceDomain, "analyst", "appeal", t0 + 200L);
                    return null;
                });
                start.countDown();
                cleanup.get(20, TimeUnit.SECONDS);
                appeal.get(20, TimeUnit.SECONDS);

                assertTrue(blocklistService.wasEverBlocked(domain));
                WhitelistEntry entry = whitelistService.list().stream()
                        .filter(e -> e.domain().equals(domain)).findFirst().orElseThrow();
                assertTrue(entry.previouslyBlocked());

                BlockLifecycle lifecycle = blocklistService.lifecycleOf(domain);
                assertEquals(2, lifecycle.transitions().size());
                assertEquals(BlockAction.BLOCK, lifecycle.transitions().get(0).action());
                BlockAction second = lifecycle.transitions().get(1).action();
                assertTrue(second == BlockAction.EXPIRE || second == BlockAction.UNBLOCK);
                assertChainLinked(lifecycle);
            }
        } finally {
            pool.shutdown();
            assertTrue(pool.awaitTermination(20, TimeUnit.SECONDS));
        }
    }

    @Test
    void concurrentCleanupAndDetectReblocksWithoutBreakingChain() throws Exception {
        protectedDomainService.add("adobe", "adobe.com");
        String[] tlds = {"com", "org", "net", "io", "co", "dev", "app", "xyz",
                "info", "biz", "site", "online", "store", "tech", "live", "shop"};
        ExecutorService pool = Executors.newFixedThreadPool(4);
        try {
            for (int i = 0; i < tlds.length; i++) {
                String domain = "ad0be." + tlds[i];
                long t0 = 60_000_000L + i * 1000L;
                blocklistService.blockAt(domain, "fraud", 50L, t0, "system");

                CountDownLatch start = new CountDownLatch(1);
                String raceDomain = domain;
                var cleanup = pool.submit(() -> {
                    await(start);
                    blocklistService.cleanupExpiredAt(t0 + 100L);
                    return null;
                });
                var detect = pool.submit(() -> {
                    await(start);
                    return detectionService.detect(raceDomain, t0 + 200L);
                });
                start.countDown();
                cleanup.get(20, TimeUnit.SECONDS);
                Verdict verdict = (Verdict) detect.get(20, TimeUnit.SECONDS);

                assertTrue(verdict.previouslyBlocked());
                assertTrue(verdict.blocked());
                assertTrue(blocklistService.isBlockedAt(domain, t0 + 300L));

                BlockLifecycle lifecycle = blocklistService.lifecycleOf(domain);
                List<BlockAction> chain = actions(lifecycle);
                assertEquals(BlockAction.BLOCK, chain.get(0));
                assertEquals(BlockAction.REBLOCK, chain.get(chain.size() - 1));
                assertTrue(chain.size() == 2 || chain.size() == 3);
                if (chain.size() == 3) {
                    assertEquals(BlockAction.EXPIRE, chain.get(1));
                }
                assertChainLinked(lifecycle);
                assertEquals(BlockStatus.ACTIVE, blocklistService.statusOf(domain, t0 + 300L));
            }
        } finally {
            pool.shutdown();
            assertTrue(pool.awaitTermination(20, TimeUnit.SECONDS));
        }
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(ex);
        }
    }

    private static List<BlockAction> actions(BlockLifecycle lifecycle) {
        return lifecycle.transitions().stream().map(BlockTransition::action).toList();
    }

    private static void assertChainLinked(BlockLifecycle lifecycle) {
        List<BlockTransition> chain = lifecycle.transitions();
        assertFalse(chain.isEmpty());
        assertTrue(lifecycle.everBlocked());
        assertEquals(BlockStatus.NONE, chain.get(0).previousStatus());
        for (int i = 1; i < chain.size(); i++) {
            assertEquals(chain.get(i - 1).newStatus(), chain.get(i).previousStatus(),
                    "状态链在第 " + i + " 处断裂");
        }
        for (BlockTransition transition : chain) {
            assertNotNull(transition.operator());
            assertFalse(transition.operator().isBlank());
            assertTrue(transition.timestampMillis() > 0);
            assertNotNull(transition.reason());
            assertNotNull(transition.previousStatus());
            assertNotNull(transition.newStatus());
        }
        assertEquals(chain.get(chain.size() - 1).newStatus(), lifecycle.currentStatus());
    }
}
