package com.github.guoyyit.domaintyposquatdetectionjava.service;

import com.github.guoyyit.domaintyposquatdetectionjava.detection.DomainNormalizer;
import com.github.guoyyit.domaintyposquatdetectionjava.model.ProtectedDomain;
import com.github.guoyyit.domaintyposquatdetectionjava.state.StateRepository;
import com.github.guoyyit.domaintyposquatdetectionjava.web.ApiException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * 受保护集合的运行期增改删。所有入站域名先归一化再存储，
 * 变更在写锁内提交并持久化，对之后的检测立即生效；
 * 已经产生的历史判定记录不被改写。
 */
@Service
public class ProtectedDomainService {

    private final StateRepository stateRepository;
    private final DomainNormalizer normalizer;

    public ProtectedDomainService(StateRepository stateRepository, DomainNormalizer normalizer) {
        this.stateRepository = stateRepository;
        this.normalizer = normalizer;
    }

    public List<ProtectedDomain> list() {
        return stateRepository.snapshotProtectedDomains();
    }

    public ProtectedDomain add(String domain, String brand) {
        if (domain == null || domain.isBlank()) {
            throw ApiException.badRequest("domain is required");
        }
        String normalized = normalizer.normalize(domain);
        String normalizedBrand = normalizeBrand(brand);
        List<ProtectedDomain> existing = stateRepository.snapshotProtectedDomains();
        for (ProtectedDomain protectedDomain : existing) {
            if (protectedDomain.getDomain().equals(normalized)) {
                throw new ApiException(409, "protected domain already exists: " + normalized);
            }
        }
        return stateRepository.addProtectedDomain(normalized, normalizedBrand);
    }

    public Optional<ProtectedDomain> update(String id, String domain, String brand) {
        if (domain == null || domain.isBlank()) {
            throw ApiException.badRequest("domain is required");
        }
        String normalized = normalizer.normalize(domain);
        String normalizedBrand = normalizeBrand(brand);
        for (ProtectedDomain protectedDomain : stateRepository.snapshotProtectedDomains()) {
            if (!protectedDomain.getId().equals(id)
                    && protectedDomain.getDomain().equals(normalized)) {
                throw new ApiException(409, "protected domain already exists: " + normalized);
            }
        }
        return stateRepository.updateProtectedDomain(id, normalized, normalizedBrand);
    }

    public boolean delete(String id) {
        return stateRepository.deleteProtectedDomain(id);
    }

    private String normalizeBrand(String brand) {
        if (brand == null || brand.isBlank()) {
            return null;
        }
        return brand.trim().toLowerCase(Locale.ROOT);
    }
}
