package com.github.guoyyit.domaintyposquatdetectionjava.service;

import com.github.guoyyit.domaintyposquatdetectionjava.model.Verdict;
import com.github.guoyyit.domaintyposquatdetectionjava.config.DetectionProperties;
import com.github.guoyyit.domaintyposquatdetectionjava.state.GuardState;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * 历史判定记录：字典变更前的历史判定仍可查询，容量有界。
 */
@Service
public class HistoryService {

    private final GuardState state;
    private final DetectionProperties properties;

    public HistoryService(GuardState state, DetectionProperties properties) {
        this.state = state;
        this.properties = properties;
    }

    public void append(Verdict verdict) {
        state.write(s -> {
            s.history.add(verdict);
            int max = properties.getMaxHistoryRecords();
            while (s.history.size() > max) {
                s.history.remove(0);
            }
            return null;
        });
    }

    public List<Verdict> queryByDomain(String normalizedDomain) {
        return state.read(s -> {
            List<Verdict> result = new ArrayList<>();
            for (Verdict verdict : s.history) {
                if (normalizedDomain != null && normalizedDomain.equals(verdict.normalizedDomain())) {
                    result.add(verdict);
                }
            }
            return result;
        });
    }

    public List<Verdict> listAll() {
        return state.read(s -> new ArrayList<>(s.history));
    }
}
