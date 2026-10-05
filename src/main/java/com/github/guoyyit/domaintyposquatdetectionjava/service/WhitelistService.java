package com.github.guoyyit.domaintyposquatdetectionjava.service;

import com.github.guoyyit.domaintyposquatdetectionjava.model.BlockAction;
import com.github.guoyyit.domaintyposquatdetectionjava.model.BlockStatus;
import com.github.guoyyit.domaintyposquatdetectionjava.model.WhitelistEntry;
import com.github.guoyyit.domaintyposquatdetectionjava.state.GuardState;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * 白名单与人工覆盖，解除操作记录操作者、时间与理由。
 * 历史封禁标记取自封禁生命周期，解封或过期清理后仍然为真。
 */
@Service
public class WhitelistService {

    private final GuardState state;
    private final BlockLifecycleService lifecycleService;

    public WhitelistService(GuardState state, BlockLifecycleService lifecycleService) {
        this.state = state;
        this.lifecycleService = lifecycleService;
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
        final String safeReason = reason == null ? "" : reason;
        return state.write(s -> {
            boolean previouslyBlocked = lifecycleService.wasEverBlocked(s, domain);
            WhitelistEntry entry = new WhitelistEntry(
                    domain, operator, nowMillis, safeReason, previouslyBlocked);
            s.whitelist.put(domain, entry);
            if (s.blocklist.remove(domain) != null) {
                lifecycleService.recordTransition(s, domain, BlockAction.UNBLOCK, operator,
                        nowMillis, safeReason, BlockStatus.UNBLOCKED);
            }
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
