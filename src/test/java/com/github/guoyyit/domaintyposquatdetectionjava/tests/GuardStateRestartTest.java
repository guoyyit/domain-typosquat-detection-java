package com.github.guoyyit.domaintyposquatdetectionjava.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.domaintyposquatdetectionjava.config.DetectionProperties;
import com.github.guoyyit.domaintyposquatdetectionjava.model.ProtectedDomain;
import com.github.guoyyit.domaintyposquatdetectionjava.persistence.SnapshotStore;
import com.github.guoyyit.domaintyposquatdetectionjava.state.GuardState;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GuardStateRestartTest {

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
    void stateSurvivesRestart() {
        GuardState before = newState();
        ProtectedDomain saved = before.write(s -> {
            ProtectedDomain entry = new ProtectedDomain("id-1", "apple", "apple.com");
            s.protectedDomains.put(entry.id(), entry);
            return entry;
        });

        GuardState after = newState();
        assertEquals(1, (int) after.read(s -> s.protectedDomains.size()));
        assertEquals(saved, after.read(s -> s.protectedDomains.get("id-1")));
        assertTrue((boolean) after.read(s -> s.auditRecords.isEmpty()));
    }

    @Test
    void cleanStartWhenNoSnapshot() {
        GuardState state = newState();
        assertEquals(0, (int) state.read(s -> s.protectedDomains.size()));
    }
}
