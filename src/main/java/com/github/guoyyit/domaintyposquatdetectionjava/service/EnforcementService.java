package com.github.guoyyit.domaintyposquatdetectionjava.service;

import com.github.guoyyit.domaintyposquatdetectionjava.config.DetectionProperties;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.DomainNormalizer;
import com.github.guoyyit.domaintyposquatdetectionjava.model.BanRecord;
import com.github.guoyyit.domaintyposquatdetectionjava.model.WhitelistEntry;
import com.github.guoyyit.domaintyposquatdetectionjava.state.StateRepository;
import com.github.guoyyit.domaintyposquatdetectionjava.web.ApiException;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * 封禁名单与白名单的并发安全管理。
 * 已封禁域名在过期或人工解除前一律不放行；过期记录被惰性/定时回收为 EXPIRED，
 * 该域名再次检测命中后可产生一条全新的 ACTIVE 记录。
 */
@Service
public class EnforcementService {

    private final StateRepository stateRepository;
    private final DetectionProperties properties;
    private final DomainNormalizer normalizer;

    public EnforcementService(StateRepository stateRepository,
                              DetectionProperties properties,
                              DomainNormalizer normalizer) {
        this.stateRepository = stateRepository;
        this.properties = properties;
        this.normalizer = normalizer;
    }

    /**
     * 封禁域名。若已存在生效中的封禁，返回该记录（幂等）；
     * 否则新建 ACTIVE 记录。白名单中的域名不能被封禁。
     */
    public BanRecord ban(String input, String reason, String detectionId, Long ttlMillis) {
        String normalized = normalizer.normalize(input);
        long now = Instant.now().toEpochMilli();
        long ttl = ttlMillis != null && ttlMillis > 0
                ? ttlMillis : properties.getBan().getDefaultTtlMillis();

        java.util.concurrent.atomic.AtomicReference<BanRecord> result =
                new java.util.concurrent.atomic.AtomicReference<>();
        stateRepository.mutate(state -> {
            if (state.getWhitelist().stream().anyMatch(w -> w.getDomain().equals(normalized))) {
                throw new ApiException(409, "domain is whitelisted: " + normalized);
            }
            expireInPlace(state, now);
            for (BanRecord ban : state.getBans()) {
                if (ban.getDomain().equals(normalized)
                        && ban.getStatus() == BanRecord.Status.ACTIVE) {
                    result.set(ban);
                    return state;
                }
            }
            BanRecord created = new BanRecord(
                    UUID.randomUUID().toString(),
                    normalized,
                    reason == null || reason.isBlank() ? "manual" : reason,
                    detectionId,
                    now,
                    now + ttl,
                    now,
                    BanRecord.Status.ACTIVE);
            state.getBans().add(created);
            result.set(created);
            return state;
        });
        return result.get();
    }

    /** 人工解封：把当前 ACTIVE 记录置为 LIFTED。 */
    public Optional<BanRecord> unban(String input) {
        String normalized = normalizer.normalize(input);
        long now = Instant.now().toEpochMilli();
        java.util.concurrent.atomic.AtomicReference<BanRecord> result =
                new java.util.concurrent.atomic.AtomicReference<>();
        stateRepository.mutate(state -> {
            for (BanRecord ban : state.getBans()) {
                if (ban.getDomain().equals(normalized)
                        && ban.getStatus() == BanRecord.Status.ACTIVE
                        && ban.getExpiresAt() > now) {
                    ban.setStatus(BanRecord.Status.LIFTED);
                    ban.setUpdatedAt(now);
                    result.set(ban);
                    break;
                }
            }
            return state;
        });
        return Optional.ofNullable(result.get());
    }

    /**
     * 加入白名单（误报申诉解除），记录操作者、理由、时间。
     * 同时把现有 ACTIVE 封禁置为 LIFTED。
     */
    public WhitelistEntry whitelist(String input, String operator, String reason) {
        if (operator == null || operator.isBlank()) {
            throw ApiException.badRequest("operator is required");
        }
        if (reason == null || reason.isBlank()) {
            throw ApiException.badRequest("reason is required");
        }
        String normalized = normalizer.normalize(input);
        long now = Instant.now().toEpochMilli();
        java.util.concurrent.atomic.AtomicReference<WhitelistEntry> result =
                new java.util.concurrent.atomic.AtomicReference<>();
        stateRepository.mutate(state -> {
            WhitelistEntry entry = state.getWhitelist().stream()
                    .filter(w -> w.getDomain().equals(normalized))
                    .findFirst()
                    .orElseGet(() -> {
                        WhitelistEntry created = new WhitelistEntry(
                                UUID.randomUUID().toString(), normalized,
                                operator, reason, now);
                        state.getWhitelist().add(created);
                        return created;
                    });
            for (BanRecord ban : state.getBans()) {
                if (ban.getDomain().equals(normalized)
                        && ban.getStatus() == BanRecord.Status.ACTIVE) {
                    ban.setStatus(BanRecord.Status.LIFTED);
                    ban.setUpdatedAt(now);
                }
            }
            result.set(entry);
            return state;
        });
        return result.get();
    }

    public boolean removeWhitelist(String input) {
        String normalized = normalizer.normalize(input);
        java.util.concurrent.atomic.AtomicBoolean removed =
                new java.util.concurrent.atomic.AtomicBoolean();
        stateRepository.mutate(state -> {
            removed.set(state.getWhitelist().removeIf(w -> w.getDomain().equals(normalized)));
            return state;
        });
        return removed.get();
    }

    /** 当前是否放行：白名单放行；否则只要存在未过期 ACTIVE 封禁即拦截。 */
    public boolean isAllowed(String input) {
        String normalized = normalizer.normalize(input);
        long now = Instant.now().toEpochMilli();
        if (stateRepository.snapshotWhitelist().stream()
                .anyMatch(w -> w.getDomain().equals(normalized))) {
            return true;
        }
        return stateRepository.snapshotBans().stream()
                .noneMatch(b -> b.getDomain().equals(normalized)
                        && b.getStatus() == BanRecord.Status.ACTIVE
                        && b.getExpiresAt() > now);
    }

    public Optional<BanRecord> getActiveBan(String input) {
        String normalized = normalizer.normalize(input);
        long now = Instant.now().toEpochMilli();
        return stateRepository.snapshotBans().stream()
                .filter(b -> b.getDomain().equals(normalized)
                        && b.getStatus() == BanRecord.Status.ACTIVE
                        && b.getExpiresAt() > now)
                .findFirst();
    }

    public List<BanRecord> listBans() {
        return stateRepository.snapshotBans();
    }

    public List<WhitelistEntry> listWhitelist() {
        return stateRepository.snapshotWhitelist();
    }

    /** 将所有已过期 ACTIVE 记录标记为 EXPIRED，返回回收条数；变更整体持久化。 */
    public int cleanupExpired() {
        long now = Instant.now().toEpochMilli();
        java.util.concurrent.atomic.AtomicInteger count =
                new java.util.concurrent.atomic.AtomicInteger();
        stateRepository.mutate(state -> {
            count.set(expireInPlace(state, now));
            return state;
        });
        return count.get();
    }

    private int expireInPlace(com.github.guoyyit.domaintyposquatdetectionjava.state.AppState state,
                              long now) {
        List<BanRecord> toExpire = new ArrayList<>();
        for (BanRecord ban : state.getBans()) {
            if (ban.getStatus() == BanRecord.Status.ACTIVE && ban.getExpiresAt() <= now) {
                toExpire.add(ban);
            }
        }
        for (BanRecord ban : toExpire) {
            ban.setStatus(BanRecord.Status.EXPIRED);
            ban.setUpdatedAt(now);
        }
        return toExpire.size();
    }
}
