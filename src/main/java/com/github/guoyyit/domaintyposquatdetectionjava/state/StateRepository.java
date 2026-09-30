package com.github.guoyyit.domaintyposquatdetectionjava.state;

import com.github.guoyyit.domaintyposquatdetectionjava.detection.DomainNormalizer;
import com.github.guoyyit.domaintyposquatdetectionjava.model.BanRecord;
import com.github.guoyyit.domaintyposquatdetectionjava.model.DetectionResult;
import com.github.guoyyit.domaintyposquatdetectionjava.model.ProtectedDomain;
import com.github.guoyyit.domaintyposquatdetectionjava.model.WhitelistEntry;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.UnaryOperator;

/**
 * 运行期状态的唯一持有者。
 * 读操作在读锁内返回不可变快照，可与并发检测并行；
 * 所有变更在写锁内作用于可变状态，随后整体原子持久化，
 * 因此“状态变更”与“落盘”对外是一个不可分割的动作。
 */
@Component
public class StateRepository {

    private final StateStore stateStore;
    private final DomainNormalizer normalizer;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    private volatile AppState state;

    public StateRepository(StateStore stateStore, DomainNormalizer normalizer) {
        this.stateStore = stateStore;
        this.normalizer = normalizer;
    }

    @PostConstruct
    public void init() {
        this.state = stateStore.load();
        if (state == null) {
            this.state = new AppState();
        }
    }

    public List<ProtectedDomain> snapshotProtectedDomains() {
        lock.readLock().lock();
        try {
            return List.copyOf(state.getProtectedDomains());
        } finally {
            lock.readLock().unlock();
        }
    }

    public ProtectedDomain addProtectedDomain(String normalizedDomain, String normalizedBrand) {
        long now = Instant.now().toEpochMilli();
        ProtectedDomain created = new ProtectedDomain(
                UUID.randomUUID().toString(), normalizedDomain, normalizedBrand, now, now);
        writePersist(s -> {
            s.getProtectedDomains().add(created);
            return s;
        });
        return created;
    }

    public Optional<ProtectedDomain> updateProtectedDomain(String id,
                                                           String normalizedDomain,
                                                           String normalizedBrand) {
        long now = Instant.now().toEpochMilli();
        java.util.concurrent.atomic.AtomicReference<ProtectedDomain> ref =
                new java.util.concurrent.atomic.AtomicReference<>();
        writePersist(s -> {
            for (ProtectedDomain domain : s.getProtectedDomains()) {
                if (domain.getId().equals(id)) {
                    domain.setDomain(normalizedDomain);
                    if (normalizedBrand != null) {
                        domain.setBrand(normalizedBrand);
                    }
                    domain.setUpdatedAt(now);
                    ref.set(domain);
                    break;
                }
            }
            return s;
        });
        return Optional.ofNullable(ref.get());
    }

    public boolean deleteProtectedDomain(String id) {
        java.util.concurrent.atomic.AtomicBoolean removed =
                new java.util.concurrent.atomic.AtomicBoolean();
        writePersist(s -> {
            removed.set(s.getProtectedDomains().removeIf(d -> d.getId().equals(id)));
            return s;
        });
        return removed.get();
    }

    public List<BanRecord> snapshotBans() {
        lock.readLock().lock();
        try {
            return List.copyOf(state.getBans());
        } finally {
            lock.readLock().unlock();
        }
    }

    public List<WhitelistEntry> snapshotWhitelist() {
        lock.readLock().lock();
        try {
            return List.copyOf(state.getWhitelist());
        } finally {
            lock.readLock().unlock();
        }
    }

    public List<DetectionResult> snapshotHistory() {
        lock.readLock().lock();
        try {
            return List.copyOf(state.getHistory());
        } finally {
            lock.readLock().unlock();
        }
    }

    /** 在写锁内修改状态并整体原子持久化，保证原子可见与崩溃恢复。 */
    public void mutate(UnaryOperator<AppState> mutation) {
        writePersist(mutation);
    }

    /** 追加一条历史判定并持久化。 */
    public void appendHistory(DetectionResult result) {
        writePersist(s -> {
            s.getHistory().add(result);
            return s;
        });
    }

    public List<DetectionResult> queryHistory(String normalizedDomain) {
        lock.readLock().lock();
        try {
            List<DetectionResult> matches = new ArrayList<>();
            for (DetectionResult result : state.getHistory()) {
                if (result.normalized().equals(normalizedDomain)) {
                    matches.add(result);
                }
            }
            return List.copyOf(matches);
        } finally {
            lock.readLock().unlock();
        }
    }

    public Optional<DetectionResult> getHistoryById(String id) {
        lock.readLock().lock();
        try {
            for (DetectionResult result : state.getHistory()) {
                if (result.id().equals(id)) {
                    return Optional.of(result);
                }
            }
            return Optional.empty();
        } finally {
            lock.readLock().unlock();
        }
    }

    private void writePersist(UnaryOperator<AppState> mutation) {
        lock.writeLock().lock();
        try {
            AppState current = state;
            AppState updated = mutation.apply(current);
            updated.setVersion(current.getVersion() + 1);
            updated.setUpdatedAt(Instant.now().toEpochMilli());
            stateStore.save(updated);
            state = updated;
        } finally {
            lock.writeLock().unlock();
        }
    }
}
