package com.github.guoyyit.domaintyposquatdetectionjava.service;

import com.github.guoyyit.domaintyposquatdetectionjava.model.AuditRecord;
import com.github.guoyyit.domaintyposquatdetectionjava.state.GuardState;
import com.github.guoyyit.domaintyposquatdetectionjava.state.StateData;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * 处置审计：所有封禁、解封、白名单、字典变更均留痕。
 */
@Service
public class AuditService {

    private final GuardState state;

    public AuditService(GuardState state) {
        this.state = state;
    }

    /**
     * 独立追加一条审计记录。
     */
    public AuditRecord record(String action, String target, String operator, String detail) {
        return state.write(s -> append(s, action, target, operator, detail));
    }

    /**
     * 在已有写事务的 {@link StateData} 上追加审计记录，保证审计与状态变更同一原子事务。
     */
    public AuditRecord appendInTransaction(StateData s, String action, String target,
                                           String operator, String detail) {
        return append(s, action, target, operator, detail);
    }

    private AuditRecord append(StateData s, String action, String target,
                               String operator, String detail) {
        long id = ++s.auditSequence;
        AuditRecord record = new AuditRecord(id, System.currentTimeMillis(), action, target,
                operator == null ? "system" : operator, detail == null ? "" : detail);
        s.auditRecords.add(record);
        return record;
    }

    public List<AuditRecord> list() {
        return state.read(s -> new ArrayList<>(s.auditRecords));
    }
}
