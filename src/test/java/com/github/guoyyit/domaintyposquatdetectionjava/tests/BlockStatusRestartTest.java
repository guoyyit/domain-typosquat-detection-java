package com.github.guoyyit.domaintyposquatdetectionjava.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.domaintyposquatdetectionjava.config.DetectionProperties;
import com.github.guoyyit.domaintyposquatdetectionjava.model.BlockEntry;
import com.github.guoyyit.domaintyposquatdetectionjava.model.BlockStatus;
import com.github.guoyyit.domaintyposquatdetectionjava.model.StatusTransition;
import com.github.guoyyit.domaintyposquatdetectionjava.model.WhitelistEntry;
import com.github.guoyyit.domaintyposquatdetectionjava.persistence.SnapshotStore;
import com.github.guoyyit.domaintyposquatdetectionjava.service.BlocklistService;
import com.github.guoyyit.domaintyposquatdetectionjava.state.GuardState;
import com.github.guoyyit.domaintyposquatdetectionjava.state.StateData;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BlockStatusRestartTest {

    @TempDir
    Path tempDir;

    private GuardState newState() {
        DetectionProperties properties = new DetectionProperties();
        properties.setDataDir(tempDir.toString());
        SnapshotStore store = new SnapshotStore(new ObjectMapper());
        GuardState state = new GuardState(properties, store);
        state.init();
        return state;
    }

    @Test
    void statusChainSurvivesRestartIdentically() {
        GuardState before = newState();
        BlocklistService blocklist = new BlocklistService(before,
                new com.github.guoyyit.domaintyposquatdetectionjava.service.AuditService(before),
                new com.github.guoyyit.domaintyposquatdetectionjava.service.BlockStatusService(before));
        long now = 7_000_000L;
        blocklist.block("restart-chain.com", "first", 100L, "ops-a", now);
        blocklist.cleanupExpiredAt(now + 150L);
        blocklist.block("restart-chain.com", "second", 100L, "ops-b", now + 200L);

        List<StatusTransition> expected = before.read(
                s -> List.copyOf(s.blockStatusChain.get("restart-chain.com")));

        GuardState after = newState();
        List<StatusTransition> restored = after.read(
                s -> List.copyOf(s.blockStatusChain.get("restart-chain.com")));
        assertEquals(expected, restored);
        assertEquals(3, restored.size());
        assertEquals(BlockStatus.BLOCKED, restored.get(2).toStatus());
        boolean reblocked = after.read(s -> s.blocklist.containsKey("restart-chain.com"));
        assertTrue(reblocked);
    }

    @Test
    void legacySnapshotWithoutChainIsUpgradedWithoutLosingHistory() throws Exception {
        Path file = tempDir.resolve("guard-state.json");
        String legacyJson = """
                {
                  "protectedDomains": {},
                  "blocklist": {
                    "still-blocked.com": {
                      "domain": "still-blocked.com",
                      "reason": "active in old version",
                      "createdAtMillis": 100,
                      "expiresAtMillis": null
                    }
                  },
                  "whitelist": {
                    "appealed.com": {
                      "domain": "appealed.com",
                      "operator": "ops-legacy",
                      "operatedAtMillis": 200,
                      "reason": "false positive",
                      "previouslyBlocked": true
                    }
                  },
                  "auditRecords": [],
                  "auditSequence": 0,
                  "history": []
                }
                """;
        Files.writeString(file, legacyJson, StandardCharsets.UTF_8);

        GuardState state = newState();
        assertTrue((boolean) state.read(s -> s.blockStatusChain.containsKey("still-blocked.com")));
        assertTrue((boolean) state.read(s -> s.blockStatusChain.containsKey("appealed.com")));

        List<StatusTransition> appealedChain =
                state.read(s -> List.copyOf(s.blockStatusChain.get("appealed.com")));
        assertEquals(2, appealedChain.size());
        assertEquals(BlockStatus.BLOCKED, appealedChain.get(0).toStatus());
        assertEquals(BlockStatus.UNBLOCKED, appealedChain.get(1).toStatus());
        assertEquals("ops-legacy", appealedChain.get(1).operator());

        // 升级后再次写盘仍是新版本格式且链不丢
        state.write(s -> null);
        GuardState reloaded = newState();
        assertTrue((boolean) reloaded.read(s -> s.blockStatusChain.containsKey("still-blocked.com")));
        assertTrue((boolean) reloaded.read(s -> s.blockStatusChain.containsKey("appealed.com")));
    }

    @Test
    void legacyWhitelistFalseBlockedDoesNotFabricateHistory() throws Exception {
        Path file = tempDir.resolve("guard-state.json");
        StateData data = new StateData();
        data.whitelist.put("clean.com", new WhitelistEntry(
                "clean.com", "ops", 1L, "never blocked", false));
        data.blocklist.put("x.com", new BlockEntry("x.com", "r", 1L, null));
        SnapshotStore store = new SnapshotStore(new ObjectMapper());
        store.store(file, store.from(data));

        GuardState state = newState();
        assertTrue((boolean) state.read(s -> !s.blockStatusChain.containsKey("clean.com")));
        assertTrue((boolean) state.read(s -> s.blockStatusChain.containsKey("x.com")));
    }
}
