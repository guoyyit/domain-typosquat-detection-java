package com.github.guoyyit.domaintyposquatdetectionjava.service;

import com.github.guoyyit.domaintyposquatdetectionjava.model.ProtectedDomain;
import com.github.guoyyit.domaintyposquatdetectionjava.normalize.DomainNormalizer;
import com.github.guoyyit.domaintyposquatdetectionjava.state.GuardState;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * 受保护域名集合的运行期维护，变更对后续检测立即生效。
 */
@Service
public class ProtectedDomainService {

    private final GuardState state;
    private final DomainNormalizer normalizer;

    public ProtectedDomainService(GuardState state, DomainNormalizer normalizer) {
        this.state = state;
        this.normalizer = normalizer;
    }

    public ProtectedDomain add(String brand, String domain) {
        String normalized = requireNormalized(domain);
        String normalizedBrand = brand == null ? "" : brand.trim().toLowerCase();
        return state.write(s -> {
            String id = UUID.randomUUID().toString();
            ProtectedDomain entry = new ProtectedDomain(id, normalizedBrand, normalized);
            s.protectedDomains.put(id, entry);
            return entry;
        });
    }

    public ProtectedDomain update(String id, String brand, String domain) {
        String normalized = requireNormalized(domain);
        String normalizedBrand = brand == null ? "" : brand.trim().toLowerCase();
        return state.write(s -> {
            ProtectedDomain existing = s.protectedDomains.get(id);
            if (existing == null) {
                throw new IllegalArgumentException("受保护域名不存在: " + id);
            }
            ProtectedDomain updated = new ProtectedDomain(id, normalizedBrand, normalized);
            s.protectedDomains.put(id, updated);
            return updated;
        });
    }

    public boolean remove(String id) {
        return state.write(s -> s.protectedDomains.remove(id) != null);
    }

    public List<ProtectedDomain> list() {
        return state.read(s -> new ArrayList<>(s.protectedDomains.values()));
    }

    private String requireNormalized(String domain) {
        String normalized = normalizer.normalize(domain);
        if (normalized == null || normalized.isBlank()) {
            throw new IllegalArgumentException("非法域名: " + domain);
        }
        return normalized;
    }
}
