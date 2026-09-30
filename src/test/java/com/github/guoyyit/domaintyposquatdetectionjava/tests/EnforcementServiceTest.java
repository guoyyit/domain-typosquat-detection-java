package com.github.guoyyit.domaintyposquatdetectionjava.tests;

import com.github.guoyyit.domaintyposquatdetectionjava.config.DetectionProperties;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.DomainNormalizer;
import com.github.guoyyit.domaintyposquatdetectionjava.model.BanRecord;
import com.github.guoyyit.domaintyposquatdetectionjava.service.EnforcementService;
import com.github.guoyyit.domaintyposquatdetectionjava.state.StateRepository;
import com.github.guoyyit.domaintyposquatdetectionjava.state.StateStore;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EnforcementServiceTest {

    private DetectionProperties properties;
    private StateRepository repository;
    private EnforcementService enforcement;
    private DomainNormalizer normalizer;

    @BeforeEach
    void setUp(@TempDir Path tempDir) {
        properties = new DetectionProperties();
        properties.getPersistence().setDir(tempDir.toString());
        normalizer = new DomainNormalizer();
        repository = new StateRepository(new StateStore(properties, new ObjectMapper()), normalizer);
        repository.init();
        enforcement = new EnforcementService(repository, properties, normalizer);
    }

    @Test
    void bannedDomainIsBlockedUntilUnban() {
        enforcement.ban("evil.com", "detected", null, null);
        assertFalse(enforcement.isAllowed("https://EVIL.com./"));

        Optional<BanRecord> lifted = enforcement.unban("evil.com");
        assertTrue(lifted.isPresent());
        assertEquals(BanRecord.Status.LIFTED, lifted.get().getStatus());
        assertTrue(enforcement.isAllowed("evil.com"));
    }

    @Test
    void expiredBanIsReapedAndDomainCanBeRebanned() {
        enforcement.ban("short.com", "detected", null, 10L);
        sleep(30);
        assertTrue(enforcement.isAllowed("short.com"), "expired ban must not block");

        int expired = enforcement.cleanupExpired();
        assertEquals(1, expired);
        assertEquals(BanRecord.Status.EXPIRED,
                repository.snapshotBans().get(0).getStatus());

        BanRecord reban = enforcement.ban("short.com", "hit again", null, 60_000L);
        assertEquals(BanRecord.Status.ACTIVE, reban.getStatus());
        assertEquals(2, repository.snapshotBans().size());
        assertFalse(enforcement.isAllowed("short.com"));
    }

    @Test
    void whitelistLiftsBanAndRecordsAudit() {
        enforcement.ban("false-positive.com", "detected", null, null);
        enforcement.whitelist("FALSE-POSITIVE.COM.", "alice", "customer appeal #42");

        assertTrue(enforcement.isAllowed("false-positive.com"));
        var entry = enforcement.listWhitelist().get(0);
        assertEquals("alice", entry.getOperator());
        assertEquals("customer appeal #42", entry.getReason());
        assertTrue(entry.getCreatedAt() > 0);
        assertEquals(BanRecord.Status.LIFTED, repository.snapshotBans().get(0).getStatus());
    }

    @Test
    void concurrentBansProduceExactlyOneActiveRecord() throws Exception {
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        List<BanRecord> records = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    synchronized (records) {
                        records.add(enforcement.ban("race.com", "race", null, null));
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(10, TimeUnit.SECONDS));
        pool.shutdown();

        long active = repository.snapshotBans().stream()
                .filter(b -> b.getStatus() == BanRecord.Status.ACTIVE)
                .count();
        assertEquals(1, active);
        assertEquals(1, records.stream().map(BanRecord::getId).distinct().count());
    }

    @Test
    void concurrentBanAndQueryNeverLeakPartialState() throws Exception {
        int writers = 8;
        int readers = 8;
        ExecutorService pool = Executors.newFixedThreadPool(writers + readers);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(writers + readers);
        for (int i = 0; i < writers; i++) {
            final int idx = i;
            pool.submit(() -> {
                try {
                    start.await();
                    enforcement.ban("domain-" + idx + ".com", "bulk", null, null);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        for (int i = 0; i < readers; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    for (int j = 0; j < 100; j++) {
                        enforcement.isAllowed("domain-" + (j % writers) + ".com");
                        enforcement.listBans();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(15, TimeUnit.SECONDS));
        pool.shutdown();
        assertEquals(writers, repository.snapshotBans().size());
    }

    private static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
