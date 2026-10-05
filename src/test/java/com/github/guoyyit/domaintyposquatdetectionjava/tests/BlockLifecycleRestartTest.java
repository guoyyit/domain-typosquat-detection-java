package com.github.guoyyit.domaintyposquatdetectionjava.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.domaintyposquatdetectionjava.config.DetectionProperties;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.EditDistance;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.FeatureDetector;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.HomoglyphMapper;
import com.github.guoyyit.domaintyposquatdetectionjava.model.BlockAction;
import com.github.guoyyit.domaintyposquatdetectionjava.model.BlockLifecycle;
import com.github.guoyyit.domaintyposquatdetectionjava.model.BlockStatus;
import com.github.guoyyit.domaintyposquatdetectionjava.model.BlockTransition;
import com.github.guoyyit.domaintyposquatdetectionjava.model.Verdict;
import com.github.guoyyit.domaintyposquatdetectionjava.normalize.DomainNormalizer;
import com.github.guoyyit.domaintyposquatdetectionjava.persistence.SnapshotStore;
import com.github.guoyyit.domaintyposquatdetectionjava.service.BlockLifecycleService;
import com.github.guoyyit.domaintyposquatdetectionjava.service.BlocklistService;
import com.github.guoyyit.domaintyposquatdetectionjava.service.DetectionService;
import com.github.guoyyit.domaintyposquatdetectionjava.service.HistoryService;
import com.github.guoyyit.domaintyposquatdetectionjava.service.ProtectedDomainService;
import com.github.guoyyit.domaintyposquatdetectionjava.service.WhitelistService;
import com.github.guoyyit.domaintyposquatdetectionjava.state.GuardState;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 状态链与历史封禁状态的重启恢复，以及旧版本快照（无状态链字段）的升级迁移。
 */
class BlockLifecycleRestartTest {

    @TempDir
    Path tempDir;

    private record Harness(GuardState state,
                           BlocklistService blocklist,
                           WhitelistService whitelist,
                           HistoryService history,
                           DetectionService detection,
                           ProtectedDomainService protectedDomains) {
    }

    private Harness newHarness() {
        DetectionProperties properties = new DetectionProperties();
        properties.setDataDir(tempDir.toString());
        properties.setBlockTtlMillis(100L);
        SnapshotStore store = new SnapshotStore(new ObjectMapper());
        GuardState state = new GuardState(properties, store);
        state.init();
        BlockLifecycleService lifecycle = new BlockLifecycleService(state);
        BlocklistService blocklist = new BlocklistService(state, lifecycle);
        WhitelistService whitelist = new WhitelistService(state, lifecycle);
        HistoryService history = new HistoryService(state, properties);
        DomainNormalizer normalizer = new DomainNormalizer();
        FeatureDetector detector = new FeatureDetector(properties, normalizer,
                new EditDistance(), new HomoglyphMapper());
        DetectionService detection = new DetectionService(state, properties, normalizer, detector,
                blocklist, whitelist, lifecycle, history);
        ProtectedDomainService protectedDomains = new ProtectedDomainService(state, normalizer);
        return new Harness(state, blocklist, whitelist, history, detection, protectedDomains);
    }

    @Test
    void stateChainAndHistorySurviveRestart() {
        long t0 = 1_000_000L;
        Harness first = newHarness();
        first.protectedDomains().add("paypal", "paypal.com");
        Verdict initial = first.detection().detect("paypa1.com", t0);
        assertTrue(initial.blocked());
        assertFalse(initial.previouslyBlocked());
        assertEquals(1, first.blocklist().cleanupExpiredAt(t0 + 200L));
        assertTrue(first.blocklist().wasEverBlocked("paypa1.com"));

        Harness second = newHarness();
        assertTrue(second.blocklist().wasEverBlocked("paypa1.com"));
        BlockLifecycle restored = second.blocklist().lifecycleOf("paypa1.com");
        assertNotNull(restored);
        assertEquals(List.of(BlockAction.BLOCK, BlockAction.EXPIRE), actions(restored));
        assertEquals(BlockStatus.EXPIRED, restored.currentStatus());
        assertEquals(1, second.history().queryByDomain("paypa1.com").size());

        Verdict reblocked = second.detection().detect("paypa1.com", t0 + 300L);
        assertTrue(reblocked.previouslyBlocked());
        assertTrue(reblocked.blocked());
        assertEquals(List.of(BlockAction.BLOCK, BlockAction.EXPIRE, BlockAction.REBLOCK),
                actions(second.blocklist().lifecycleOf("paypa1.com")));

        Harness third = newHarness();
        assertTrue(third.blocklist().wasEverBlocked("paypa1.com"));
        BlockLifecycle lifecycle = third.blocklist().lifecycleOf("paypa1.com");
        assertEquals(List.of(BlockAction.BLOCK, BlockAction.EXPIRE, BlockAction.REBLOCK),
                actions(lifecycle));
        assertEquals(BlockStatus.EXPIRED, third.blocklist().statusOf("paypa1.com", t0 + 500L));
        assertEquals(2, third.history().queryByDomain("paypa1.com").size());
        assertChainLinked(lifecycle);
    }

    @Test
    void whitelistHistorySurvivesRestartAndRevoke() {
        long t0 = 2_000_000L;
        Harness first = newHarness();
        first.blocklist().blockAt("appealed.example", "fraud", null, t0, "system");
        first.whitelist().exemptAt("appealed.example", "analyst", "approved", t0 + 10L);

        Harness second = newHarness();
        assertTrue(second.blocklist().wasEverBlocked("appealed.example"));
        assertTrue(second.whitelist().list().get(0).previouslyBlocked());

        second.whitelist().revoke("appealed.example");
        Harness third = newHarness();
        assertTrue(third.blocklist().wasEverBlocked("appealed.example"));
        BlockLifecycle lifecycle = third.blocklist().lifecycleOf("appealed.example");
        assertEquals(List.of(BlockAction.BLOCK, BlockAction.UNBLOCK), actions(lifecycle));
        assertEquals(BlockStatus.UNBLOCKED, lifecycle.currentStatus());
    }

    @Test
    void legacySnapshotWithoutLifecycleIsMigrated() throws Exception {
        String legacyJson = """
                {
                  "protectedDomains": {},
                  "blocklist": {
                    "old-expired.example": {"domain": "old-expired.example", "reason": "fraud",
                        "createdAtMillis": 100, "expiresAtMillis": 200}
                  },
                  "whitelist": {
                    "appealed.example": {"domain": "appealed.example", "operator": "ops",
                        "operatedAtMillis": 300, "reason": "reviewed", "previouslyBlocked": true}
                  },
                  "auditRecords": [],
                  "auditSequence": 0,
                  "history": []
                }
                """;
        Files.writeString(tempDir.resolve("guard-state.json"), legacyJson);

        Harness harness = newHarness();
        assertTrue(harness.blocklist().wasEverBlocked("old-expired.example"));
        assertEquals(BlockStatus.EXPIRED, harness.blocklist().statusOf(
                "old-expired.example", System.currentTimeMillis()));
        assertEquals(List.of(BlockAction.BLOCK, BlockAction.EXPIRE),
                actions(harness.blocklist().lifecycleOf("old-expired.example")));

        assertTrue(harness.blocklist().wasEverBlocked("appealed.example"));
        BlockLifecycle appealed = harness.blocklist().lifecycleOf("appealed.example");
        assertEquals(List.of(BlockAction.BLOCK, BlockAction.UNBLOCK), actions(appealed));
        assertEquals(BlockStatus.UNBLOCKED, appealed.currentStatus());
        assertEquals("ops", appealed.transitions().get(1).operator());

        assertFalse(harness.blocklist().wasEverBlocked("never-blocked.example"));
        assertEquals(BlockStatus.NONE, harness.blocklist().statusOf(
                "never-blocked.example", System.currentTimeMillis()));
    }

    private static List<BlockAction> actions(BlockLifecycle lifecycle) {
        return lifecycle.transitions().stream().map(BlockTransition::action).toList();
    }

    private static void assertChainLinked(BlockLifecycle lifecycle) {
        List<BlockTransition> chain = lifecycle.transitions();
        assertEquals(BlockStatus.NONE, chain.get(0).previousStatus());
        for (int i = 1; i < chain.size(); i++) {
            assertEquals(chain.get(i - 1).newStatus(), chain.get(i).previousStatus());
        }
    }
}
