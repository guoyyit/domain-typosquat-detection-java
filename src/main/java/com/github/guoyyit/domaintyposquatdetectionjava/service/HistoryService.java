package com.github.guoyyit.domaintyposquatdetectionjava.service;

import com.github.guoyyit.domaintyposquatdetectionjava.detection.DomainNormalizer;
import com.github.guoyyit.domaintyposquatdetectionjava.model.DetectionResult;
import com.github.guoyyit.domaintyposquatdetectionjava.state.StateRepository;
import com.github.guoyyit.domaintyposquatdetectionjava.web.ApiException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

/**
 * 历史判定查询。字典变更不影响已落盘的历史记录。
 */
@Service
public class HistoryService {

    private final StateRepository stateRepository;
    private final DomainNormalizer normalizer;

    public HistoryService(StateRepository stateRepository, DomainNormalizer normalizer) {
        this.stateRepository = stateRepository;
        this.normalizer = normalizer;
    }

    public List<DetectionResult> all() {
        return stateRepository.snapshotHistory();
    }

    public List<DetectionResult> byDomain(String input) {
        if (input == null || input.isBlank()) {
            throw ApiException.badRequest("domain is required");
        }
        return stateRepository.queryHistory(normalizer.normalize(input));
    }

    public Optional<DetectionResult> byId(String id) {
        return stateRepository.getHistoryById(id);
    }
}
