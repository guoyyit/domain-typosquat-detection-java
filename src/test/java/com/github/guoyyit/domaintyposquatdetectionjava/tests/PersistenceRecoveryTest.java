package com.github.guoyyit.domaintyposquatdetectionjava.tests;

import com.github.guoyyit.domaintyposquatdetectionjava.model.AuditRecord;
import com.github.guoyyit.domaintyposquatdetectionjava.model.BlockEntry;
import com.github.guoyyit.domaintyposquatdetectionjava.model.ProtectedDomain;
import com.github.guoyyit.domaintyposquatdetectionjava.persistence.SnapshotStore;
import com.github.guoyyit.domaintyposquatdetectionjava.state.GuardState;
import com.github.guoyyit.domaintyposquatdetectionjava.state.StateData;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PersistenceRecoveryTest {

    private final SnapshotStore store = new SnapshotStore(new com.fasterxml.jackson.databind.ObjectMapper());

    @TempDir
    Path tempDir;

    @Test
    void snapshotRoundTripPreservesAllState() {
        StateData original = new StateData();
        original.protectedDomains.put("p1", new ProtectedDomain("p1", "brand", "brand.com"));
        original.blocklist.put("evil.com", new BlockEntry("evil.com", "auto", 100L, 200L));
        original.whitelist.put("ok.com",
                new com.github.guoyyit.domaintyposquatdetectionjava.model.WhitelistEntry(
                        "ok.com", "ops", 100L, "reviewed", true));
        original.auditSequence = 3L;
        original.auditRecords.add(new AuditRecord(1L, 100L, "BLOCK", "evil.com", "system", "x"));

        Path file = tempDir.resolve("state.json");
        store.store(file, store.from(original));
        assertTrue(java.nio.file.Files.exists(file));
        assertFalse(java.nio.file.Files.exists(file.resolveSibling("state.json.tmp")));

        StateData restored = new StateData();
        store.restoreInto(store.load(file), restored);

        assertEquals(original.protectedDomains, restored.protectedDomains);
        assertEquals(original.blocklist, restored.blocklist);
        assertEquals(original.whitelist, restored.whitelist);
        assertEquals(List.of(new AuditRecord(1L, 100L, "BLOCK", "evil.com", "system", "x")),
                restored.auditRecords);
        assertEquals(3L, restored.auditSequence);
    }

    @Test
    void missingSnapshotRestoresEmptyState() {
        StateData state = new StateData();
        store.restoreInto(store.load(tempDir.resolve("absent.json")), state);
        assertTrue(state.protectedDomains.isEmpty());
        assertEquals(0L, state.auditSequence);
    }

    @Test
    void overwriteIsAtomicAndLeavesNoPartialFile() {
        Path file = tempDir.resolve("state.json");
        StateData first = new StateData();
        first.protectedDomains.put("a", new ProtectedDomain("a", "a", "a.com"));
        store.store(file, store.from(first));

        StateData second = new StateData();
        second.protectedDomains.put("b", new ProtectedDomain("b", "b", "b.com"));
        store.store(file, store.from(second));

        StateData restored = new StateData();
        store.restoreInto(store.load(file), restored);
        assertTrue(restored.protectedDomains.containsKey("b"));
        assertFalse(restored.protectedDomains.containsKey("a"));
        assertFalse(java.nio.file.Files.exists(file.resolveSibling("state.json.tmp")));
    }
}
