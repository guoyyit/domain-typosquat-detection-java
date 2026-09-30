package com.github.guoyyit.domaintyposquatdetectionjava.persistence;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.guoyyit.domaintyposquatdetectionjava.model.PersistentSnapshot;
import com.github.guoyyit.domaintyposquatdetectionjava.state.StateData;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.LinkedHashMap;
import java.util.List;

/**
 * 状态快照的持久化：JSON 序列化 + 临时文件 + 原子移动，杜绝部分写入。
 */
@Component
public class SnapshotStore {

    private final ObjectMapper objectMapper;

    public SnapshotStore(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public synchronized PersistentSnapshot load(Path file) {
        if (!Files.exists(file)) {
            return null;
        }
        try {
            return objectMapper.readValue(file.toFile(), PersistentSnapshot.class);
        } catch (IOException ex) {
            throw new IllegalStateException("无法读取状态快照: " + file, ex);
        }
    }

    public synchronized void store(Path file, PersistentSnapshot snapshot) {
        try {
            Path parent = file.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
            objectMapper.writerWithDefaultPrettyPrinter().writeValue(tmp.toFile(), snapshot);
            try {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (IOException atomicFailed) {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException ex) {
            throw new IllegalStateException("无法写入状态快照: " + file, ex);
        }
    }

    public PersistentSnapshot from(StateData state) {
        synchronized (state) {
            return new PersistentSnapshot(
                    new LinkedHashMap<>(state.protectedDomains),
                    new LinkedHashMap<>(state.blocklist),
                    new LinkedHashMap<>(state.whitelist),
                    List.copyOf(state.auditRecords),
                    state.auditSequence,
                    List.copyOf(state.history));
        }
    }

    public void restoreInto(PersistentSnapshot snapshot, StateData state) {
        if (snapshot == null) {
            return;
        }
        state.protectedDomains.clear();
        if (snapshot.protectedDomains() != null) {
            state.protectedDomains.putAll(snapshot.protectedDomains());
        }
        state.blocklist.clear();
        if (snapshot.blocklist() != null) {
            state.blocklist.putAll(snapshot.blocklist());
        }
        state.whitelist.clear();
        if (snapshot.whitelist() != null) {
            state.whitelist.putAll(snapshot.whitelist());
        }
        state.auditRecords.clear();
        if (snapshot.auditRecords() != null) {
            state.auditRecords.addAll(snapshot.auditRecords());
        }
        state.history.clear();
        if (snapshot.history() != null) {
            state.history.addAll(snapshot.history());
        }
        state.auditSequence = snapshot.auditSequence();
    }
}
