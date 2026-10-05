package com.github.guoyyit.domaintyposquatdetectionjava.model;

import java.util.List;
import java.util.Map;

/**
 * 需要持久化的全量状态快照，以单文件原子写入保证崩溃一致性。
 * {@code blockLifecycles} 为升级新增字段，旧版本快照中缺失时反序列化为 {@code null}，
 * 由加载方按封禁名单与白名单重建，保证升级不丢历史封禁状态。
 */
public record PersistentSnapshot(
        Map<String, ProtectedDomain> protectedDomains,
        Map<String, BlockEntry> blocklist,
        Map<String, WhitelistEntry> whitelist,
        List<AuditRecord> auditRecords,
        long auditSequence,
        List<Verdict> history,
        Map<String, BlockLifecycle> blockLifecycles
) {
}
