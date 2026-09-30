package com.github.guoyyit.domaintyposquatdetectionjava.model;

/**
 * 处置审计记录。
 */
public record AuditRecord(
        long id,
        long timestampMillis,
        String action,
        String target,
        String operator,
        String detail
) {
}
