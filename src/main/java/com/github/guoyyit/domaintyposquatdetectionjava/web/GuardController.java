package com.github.guoyyit.domaintyposquatdetectionjava.web;

import com.github.guoyyit.domaintyposquatdetectionjava.model.AuditRecord;
import com.github.guoyyit.domaintyposquatdetectionjava.model.BatchItemResult;
import com.github.guoyyit.domaintyposquatdetectionjava.model.BlockEntry;
import com.github.guoyyit.domaintyposquatdetectionjava.model.ProtectedDomain;
import com.github.guoyyit.domaintyposquatdetectionjava.model.Verdict;
import com.github.guoyyit.domaintyposquatdetectionjava.model.WhitelistEntry;
import com.github.guoyyit.domaintyposquatdetectionjava.normalize.DomainNormalizer;
import com.github.guoyyit.domaintyposquatdetectionjava.service.AuditService;
import com.github.guoyyit.domaintyposquatdetectionjava.service.BatchDetectionService;
import com.github.guoyyit.domaintyposquatdetectionjava.service.BlocklistService;
import com.github.guoyyit.domaintyposquatdetectionjava.service.DetectionService;
import com.github.guoyyit.domaintyposquatdetectionjava.service.HistoryService;
import com.github.guoyyit.domaintyposquatdetectionjava.service.ProtectedDomainService;
import com.github.guoyyit.domaintyposquatdetectionjava.service.WhitelistService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * 检测、字典、封禁、白名单与审计的 HTTP 接口。
 */
@RestController
@RequestMapping("/api")
public class GuardController {

    private final DetectionService detectionService;
    private final BatchDetectionService batchDetectionService;
    private final ProtectedDomainService protectedDomainService;
    private final BlocklistService blocklistService;
    private final WhitelistService whitelistService;
    private final AuditService auditService;
    private final HistoryService historyService;
    private final DomainNormalizer normalizer;

    public GuardController(DetectionService detectionService,
                           BatchDetectionService batchDetectionService,
                           ProtectedDomainService protectedDomainService,
                           BlocklistService blocklistService,
                           WhitelistService whitelistService,
                           AuditService auditService,
                           HistoryService historyService,
                           DomainNormalizer normalizer) {
        this.detectionService = detectionService;
        this.batchDetectionService = batchDetectionService;
        this.protectedDomainService = protectedDomainService;
        this.blocklistService = blocklistService;
        this.whitelistService = whitelistService;
        this.auditService = auditService;
        this.historyService = historyService;
        this.normalizer = normalizer;
    }

    @PostMapping("/detect")
    public Verdict detect(@RequestBody Map<String, String> body) {
        return detectionService.detect(body.get("domain"));
    }

    @PostMapping("/detect/batch")
    public List<BatchItemResult> detectBatch(@RequestBody Map<String, List<String>> body) {
        return batchDetectionService.detectBatch(body.getOrDefault("domains", List.of()));
    }

    @GetMapping("/protected")
    public List<ProtectedDomain> listProtected() {
        return protectedDomainService.list();
    }

    @PostMapping("/protected")
    public ProtectedDomain addProtected(@RequestBody Map<String, String> body) {
        ProtectedDomain added = protectedDomainService.add(body.get("brand"), body.get("domain"));
        auditService.record("PROTECTED_ADD", added.id(), body.get("operator"), added.domain());
        return added;
    }

    @PostMapping("/protected/{id}")
    public ProtectedDomain updateProtected(@PathVariable String id, @RequestBody Map<String, String> body) {
        ProtectedDomain updated = protectedDomainService.update(id, body.get("brand"), body.get("domain"));
        auditService.record("PROTECTED_UPDATE", id, body.get("operator"), updated.domain());
        return updated;
    }

    @DeleteMapping("/protected/{id}")
    public Map<String, Boolean> removeProtected(@PathVariable String id,
                                                @RequestParam(required = false) String operator) {
        boolean removed = protectedDomainService.remove(id);
        if (removed) {
            auditService.record("PROTECTED_REMOVE", id, operator, null);
        }
        return Map.of("removed", removed);
    }

    @GetMapping("/blocklist")
    public List<BlockEntry> listBlocked() {
        return blocklistService.list();
    }

    @PostMapping("/blocklist/block")
    public BlockEntry block(@RequestBody Map<String, Object> body) {
        String domain = normalizer.normalize((String) body.get("domain"));
        Long ttl = body.get("ttlMillis") == null ? null : ((Number) body.get("ttlMillis")).longValue();
        BlockEntry entry = blocklistService.block(domain, str(body, "reason"), ttl);
        auditService.record("BLOCK", domain, str(body, "operator"), entry.reason());
        return entry;
    }

    @PostMapping("/blocklist/unblock")
    public Map<String, Boolean> unblock(@RequestBody Map<String, String> body) {
        String domain = normalizer.normalize(body.get("domain"));
        boolean removed = blocklistService.unblock(domain);
        if (removed) {
            auditService.record("UNBLOCK", domain, body.get("operator"), body.get("reason"));
        }
        return Map.of("unblocked", removed);
    }

    @PostMapping("/blocklist/cleanup")
    public Map<String, Integer> cleanup() {
        return Map.of("removed", blocklistService.cleanupExpired());
    }

    @GetMapping("/whitelist")
    public List<WhitelistEntry> listWhitelisted() {
        return whitelistService.list();
    }

    @PostMapping("/whitelist")
    public WhitelistEntry exempt(@RequestBody Map<String, String> body) {
        String domain = normalizer.normalize(body.get("domain"));
        WhitelistEntry entry = whitelistService.exempt(domain, body.get("operator"), body.get("reason"));
        auditService.record("WHITELIST_ADD", domain, entry.operator(), entry.reason());
        return entry;
    }

    @DeleteMapping("/whitelist/{domain}")
    public Map<String, Boolean> revokeWhitelist(@PathVariable String domain,
                                                @RequestParam(required = false) String operator) {
        String normalized = normalizer.normalize(domain);
        boolean revoked = whitelistService.revoke(normalized);
        if (revoked) {
            auditService.record("WHITELIST_REVOKE", normalized, operator, null);
        }
        return Map.of("revoked", revoked);
    }

    @GetMapping("/audit")
    public List<AuditRecord> audit() {
        return auditService.list();
    }

    @GetMapping("/history/{domain}")
    public List<Verdict> history(@PathVariable String domain) {
        return historyService.queryByDomain(normalizer.normalize(domain));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, String> handleBadRequest(IllegalArgumentException ex) {
        return Map.of("error", ex.getMessage() == null ? "非法请求" : ex.getMessage());
    }

    private String str(Map<String, Object> body, String key) {
        Object value = body.get(key);
        return value == null ? null : value.toString();
    }
}
