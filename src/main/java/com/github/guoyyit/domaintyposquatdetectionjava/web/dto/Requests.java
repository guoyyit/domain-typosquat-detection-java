package com.github.guoyyit.domaintyposquatdetectionjava.web.dto;

import java.util.List;

/**
 * REST 请求体定义。
 */
public final class Requests {

    private Requests() {
    }

    public record DetectRequest(String domain) {
    }

    public record BatchDetectRequest(List<String> domains) {
    }

    public record ProtectedDomainRequest(String domain, String brand) {
    }

    public record BanRequest(String domain, String reason, Long ttlMillis) {
    }

    public record WhitelistRequest(String domain, String operator, String reason) {
    }
}
