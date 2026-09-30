package com.github.guoyyit.domaintyposquatdetectionjava.web;

import com.github.guoyyit.domaintyposquatdetectionjava.model.BanRecord;
import com.github.guoyyit.domaintyposquatdetectionjava.model.BatchItemResult;
import com.github.guoyyit.domaintyposquatdetectionjava.model.DetectionResult;
import com.github.guoyyit.domaintyposquatdetectionjava.model.ProtectedDomain;
import com.github.guoyyit.domaintyposquatdetectionjava.model.WhitelistEntry;
import com.github.guoyyit.domaintyposquatdetectionjava.service.BatchDetectionService;
import com.github.guoyyit.domaintyposquatdetectionjava.service.DetectionService;
import com.github.guoyyit.domaintyposquatdetectionjava.service.EnforcementService;
import com.github.guoyyit.domaintyposquatdetectionjava.service.HistoryService;
import com.github.guoyyit.domaintyposquatdetectionjava.service.ProtectedDomainService;
import com.github.guoyyit.domaintyposquatdetectionjava.web.dto.Requests;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * 检测、受保护集合、封禁/白名单与历史查询的 HTTP 入口。
 */
@RestController
@RequestMapping("/api")
public class ApiController {

    private final DetectionService detectionService;
    private final BatchDetectionService batchDetectionService;
    private final ProtectedDomainService protectedDomainService;
    private final EnforcementService enforcementService;
    private final HistoryService historyService;

    public ApiController(DetectionService detectionService,
                         BatchDetectionService batchDetectionService,
                         ProtectedDomainService protectedDomainService,
                         EnforcementService enforcementService,
                         HistoryService historyService) {
        this.detectionService = detectionService;
        this.batchDetectionService = batchDetectionService;
        this.protectedDomainService = protectedDomainService;
        this.enforcementService = enforcementService;
        this.historyService = historyService;
    }

    @PostMapping("/detect")
    public DetectionResult detect(@RequestBody Requests.DetectRequest request) {
        validateBody(request != null, "request body required");
        return detectionService.detect(request.domain());
    }

    @PostMapping("/detect/batch")
    public List<BatchItemResult> detectBatch(@RequestBody Requests.BatchDetectRequest request) {
        validateBody(request != null && request.domains() != null, "domains required");
        return batchDetectionService.detectBatch(request.domains());
    }

    @GetMapping("/protected")
    public List<ProtectedDomain> listProtected() {
        return protectedDomainService.list();
    }

    @PostMapping("/protected")
    public ResponseEntity<ProtectedDomain> addProtected(
            @RequestBody Requests.ProtectedDomainRequest request) {
        validateBody(request != null, "request body required");
        ProtectedDomain created = protectedDomainService.add(request.domain(), request.brand());
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    @PutMapping("/protected/{id}")
    public ProtectedDomain updateProtected(@PathVariable String id,
                                           @RequestBody Requests.ProtectedDomainRequest request) {
        validateBody(request != null, "request body required");
        return protectedDomainService.update(id, request.domain(), request.brand())
                .orElseThrow(() -> ApiException.notFound("protected domain not found: " + id));
    }

    @DeleteMapping("/protected/{id}")
    public ResponseEntity<Void> deleteProtected(@PathVariable String id) {
        if (!protectedDomainService.delete(id)) {
            throw ApiException.notFound("protected domain not found: " + id);
        }
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/bans")
    public BanRecord ban(@RequestBody Requests.BanRequest request) {
        validateBody(request != null && request.domain() != null, "domain required");
        return enforcementService.ban(request.domain(), request.reason(), null, request.ttlMillis());
    }

    @DeleteMapping("/bans")
    public BanRecord unban(@RequestParam String domain) {
        return enforcementService.unban(domain)
                .orElseThrow(() -> ApiException.notFound("no active ban for: " + domain));
    }

    @GetMapping("/bans")
    public List<BanRecord> listBans() {
        return enforcementService.listBans();
    }

    @PostMapping("/whitelist")
    public WhitelistEntry whitelist(@RequestBody Requests.WhitelistRequest request) {
        validateBody(request != null, "request body required");
        return enforcementService.whitelist(request.domain(), request.operator(), request.reason());
    }

    @DeleteMapping("/whitelist")
    public ResponseEntity<Void> removeWhitelist(@RequestParam String domain) {
        if (!enforcementService.removeWhitelist(domain)) {
            throw ApiException.notFound("not whitelisted: " + domain);
        }
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/whitelist")
    public List<WhitelistEntry> listWhitelist() {
        return enforcementService.listWhitelist();
    }

    @GetMapping("/history")
    public List<DetectionResult> history(@RequestParam(required = false) String domain) {
        return domain == null || domain.isBlank()
                ? historyService.all()
                : historyService.byDomain(domain);
    }

    @GetMapping("/history/{id}")
    public DetectionResult historyById(@PathVariable String id) {
        return historyService.byId(id)
                .orElseThrow(() -> ApiException.notFound("history record not found: " + id));
    }

    private void validateBody(boolean condition, String message) {
        if (!condition) {
            throw ApiException.badRequest(message);
        }
    }
}
