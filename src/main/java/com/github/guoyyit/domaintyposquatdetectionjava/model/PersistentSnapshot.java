package com.github.guoyyit.domaintyposquatdetectionjava.model;

import java.util.List;
import java.util.Map;

/**
 * 需要持久化的全量状态快照，以单文件原子写入保证崩溃一致性。
 */
public record PersistentSnapshot(
        Map<String, ProtectedDomain> protectedDomains,
        Map<String, BlockEntry> blocklist,
        Map<String, WhitelistEntry> whitelist,
        List<AuditRecord> auditRecords,
        long auditSequence,
        List<Verdict> history
) {
}
