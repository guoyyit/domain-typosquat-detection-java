package com.github.guoyyit.domaintyposquatdetectionjava.state;

import com.github.guoyyit.domaintyposquatdetectionjava.config.DetectionProperties;
import com.github.guoyyit.domaintyposquatdetectionjava.model.PersistentSnapshot;
import com.github.guoyyit.domaintyposquatdetectionjava.persistence.SnapshotStore;
import com.github.guoyyit.domaintyposquatdetectionjava.service.BlockStatusService;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Function;

/**
 * 全局状态门面：读写锁保护并发访问，写操作在同一事务内原子持久化。
 */
@Component
public class GuardState {

    private static final Logger log = LoggerFactory.getLogger(GuardState.class);

    private final DetectionProperties properties;
    private final SnapshotStore snapshotStore;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private StateData data = new StateData();
    private Path snapshotFile;

    public GuardState(DetectionProperties properties, SnapshotStore snapshotStore) {
        this.properties = properties;
        this.snapshotStore = snapshotStore;
    }

    @PostConstruct
    public void init() {
        snapshotFile = Path.of(properties.getDataDir(), "guard-state.json");
        PersistentSnapshot snapshot = snapshotStore.load(snapshotFile);
        if (snapshot != null) {
            snapshotStore.restoreInto(snapshot, data);
            BlockStatusService.backfillFromLegacySnapshot(data);
            log.info("恢复状态快照：受保护域名 {} 条，封禁 {} 条，白名单 {} 条，审计 {} 条",
                    data.protectedDomains.size(), data.blocklist.size(),
                    data.whitelist.size(), data.auditRecords.size());
        }
    }

    public <T> T read(Function<StateData, T> query) {
        lock.readLock().lock();
        try {
            return query.apply(data);
        } finally {
            lock.readLock().unlock();
        }
    }

    public <T> T write(Function<StateData, T> mutation) {
        lock.writeLock().lock();
        try {
            T result = mutation.apply(data);
            persist();
            return result;
        } finally {
            lock.writeLock().unlock();
        }
    }

    private void persist() {
        snapshotStore.store(snapshotFile, snapshotStore.from(data));
    }
}
