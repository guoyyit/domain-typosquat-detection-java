package com.github.guoyyit.domaintyposquatdetectionjava.state;

import com.github.guoyyit.domaintyposquatdetectionjava.model.AuditRecord;
import com.github.guoyyit.domaintyposquatdetectionjava.model.BlockEntry;
import com.github.guoyyit.domaintyposquatdetectionjava.model.ProtectedDomain;
import com.github.guoyyit.domaintyposquatdetectionjava.model.StatusTransition;
import com.github.guoyyit.domaintyposquatdetectionjava.model.Verdict;
import com.github.guoyyit.domaintyposquatdetectionjava.model.WhitelistEntry;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 运行期全部可变状态，仅允许在 {@link GuardState} 的锁保护下访问。
 */
public class StateData {

    public final Map<String, ProtectedDomain> protectedDomains = new LinkedHashMap<>();
    public final Map<String, BlockEntry> blocklist = new HashMap<>();
    public final Map<String, WhitelistEntry> whitelist = new HashMap<>();
    public final List<AuditRecord> auditRecords = new ArrayList<>();
    public final List<Verdict> history = new ArrayList<>();
    public final Map<String, List<StatusTransition>> blockStatusChain = new LinkedHashMap<>();
    public long auditSequence = 0L;
}
