package com.github.guoyyit.domaintyposquatdetectionjava.service;

import com.github.guoyyit.domaintyposquatdetectionjava.model.WhitelistEntry;
import com.github.guoyyit.domaintyposquatdetectionjava.state.GuardState;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * 白名单与人工覆盖，解除操作记录操作者、时间与理由。
 */
@Service
public class WhitelistService {

    private final GuardState state;
    private final BlocklistService blocklistService;

    public WhitelistService(GuardState state, BlocklistService blocklistService) {
        this.state = state;
        this.blocklistService = blocklistService;
    }

    public WhitelistEntry exempt(String domain, String operator, String reason) {
        return exemptAt(domain, operator, reason, System.currentTimeMillis());
    }

    public WhitelistEntry exemptAt(String domain, String operator, String reason, long nowMillis) {
        if (domain == null || domain.isBlank()) {
            throw new IllegalArgumentException("域名不能为空");
        }
        if (operator == null || operator.isBlank()) {
            throw new IllegalArgumentException("操作者不能为空");
        }
        String normalizedReason = reason == null ? "" : reason;
        return state.write(s -> {
            boolean previouslyBlocked = blocklistService
                    .unblockInTransaction(s, domain, operator, normalizedReason, nowMillis);
            WhitelistEntry entry = new WhitelistEntry(
                    domain, operator, nowMillis, normalizedReason, previouslyBlocked);
            s.whitelist.put(domain, entry);
            return entry;
        });
    }

    public boolean revoke(String domain) {
        return state.write(s -> s.whitelist.remove(domain) != null);
    }

    public boolean isWhitelisted(String domain) {
        return state.read(s -> s.whitelist.containsKey(domain));
    }

    public List<WhitelistEntry> list() {
        return state.read(s -> new ArrayList<>(s.whitelist.values()));
    }
}
