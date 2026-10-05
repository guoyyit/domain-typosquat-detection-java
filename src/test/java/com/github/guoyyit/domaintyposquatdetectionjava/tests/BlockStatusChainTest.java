package com.github.guoyyit.domaintyposquatdetectionjava.tests;

import com.github.guoyyit.domaintyposquatdetectionjava.model.BlockStatus;
import com.github.guoyyit.domaintyposquatdetectionjava.model.RiskLevel;
import com.github.guoyyit.domaintyposquatdetectionjava.model.StatusTransition;
import com.github.guoyyit.domaintyposquatdetectionjava.model.Verdict;
import com.github.guoyyit.domaintyposquatdetectionjava.service.BlocklistService;
import com.github.guoyyit.domaintyposquatdetectionjava.service.DetectionService;
import com.github.guoyyit.domaintyposquatdetectionjava.service.ProtectedDomainService;
import com.github.guoyyit.domaintyposquatdetectionjava.service.WhitelistService;
import com.github.guoyyit.domaintyposquatdetectionjava.normalize.DomainNormalizer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
class BlockStatusChainTest {

    @Autowired private BlocklistService blocklistService;
    @Autowired private WhitelistService whitelistService;
    @Autowired private DetectionService detectionService;
    @Autowired private ProtectedDomainService protectedDomainService;
    @Autowired private DomainNormalizer normalizer;

    @Test
    void expiredThenRedetectKeepsHistoricalBlock() {
        protectedDomainService.add("microsoft", "microsoft.com");
        String input = "micros\u043eft.com";
        long now = 10_000_000L;

        String domain = normalizer.normalize(input);
        blocklistService.block(domain, "first offense", 100L, "ops-alice", now);
        assertEquals(1, blocklistService.cleanupExpiredAt(now + 200L, "system", "cleanup"));
        assertFalse(blocklistService.isBlockedAt(domain, now + 200L));
        assertTrue(blocklistService.wasEverBlocked(domain));

        Verdict verdict = detectionService.detect(input, now + 300L);
        assertTrue(verdict.previouslyBlocked());
        assertTrue(verdict.blocked());
        assertEquals(RiskLevel.HIGH, verdict.riskLevel());

        List<StatusTransition> chain = blocklistService.statusChain(domain);
        assertEquals(3, chain.size());
        assertTransition(chain.get(0), "BLOCK", null, BlockStatus.BLOCKED, "ops-alice");
        assertTransition(chain.get(1), "EXPIRE", BlockStatus.BLOCKED, BlockStatus.EXPIRED, "system");
        assertTransition(chain.get(2), "REBLOCK", BlockStatus.EXPIRED, BlockStatus.BLOCKED, "system");
    }

    @Test
    void expiredThenWhitelistAppealKeepsHistoricalBlock() {
        String domain = "chain-expired-appeal.com";
        long now = 20_000_000L;
        blocklistService.block(domain, "first offense", 100L, "ops-alice", now);
        blocklistService.cleanupExpiredAt(now + 200L);

        whitelistService.exemptAt(domain, "reviewer-bob", "appeal approved", now + 300L);
        assertTrue(blocklistService.wasEverBlocked(domain));
        assertTrue(whitelistService.list().stream()
                .filter(e -> e.domain().equals(domain))
                .findFirst().orElseThrow().previouslyBlocked());

        List<StatusTransition> chain = blocklistService.statusChain(domain);
        assertEquals(2, chain.size());
        assertTransition(chain.get(0), "BLOCK", null, BlockStatus.BLOCKED, "ops-alice");
        assertTransition(chain.get(1), "EXPIRE", BlockStatus.BLOCKED, BlockStatus.EXPIRED, "system");
    }

    @Test
    void manualUnblockThenAppealShowsHistoricalBlock() {
        String domain = "chain-unblocked.com";
        long now = 30_000_000L;
        blocklistService.block(domain, "manual review", null, "ops-alice", now);
        assertTrue(blocklistService.unblock(domain, "reviewer-bob", "false positive", now + 100L));
        assertFalse(blocklistService.isBlockedAt(domain, now + 200L));

        whitelistService.exemptAt(domain, "reviewer-carol", "appeal approved", now + 300L);

        assertTrue(blocklistService.wasEverBlocked(domain));
        List<StatusTransition> chain = blocklistService.statusChain(domain);
        assertEquals(2, chain.size());
        assertTransition(chain.get(0), "BLOCK", null, BlockStatus.BLOCKED, "ops-alice");
        assertTransition(chain.get(1), "UNBLOCK", BlockStatus.BLOCKED, BlockStatus.UNBLOCKED,
                "reviewer-bob");
    }

    @Test
    void repeatedBlocksBuildContinuousChainWithoutOverwritingHistory() {
        String domain = "chain-repeat.com";
        long now = 40_000_000L;

        blocklistService.block(domain, "block-1", 100L, "ops-1", now);
        blocklistService.cleanupExpiredAt(now + 150L);
        blocklistService.block(domain, "block-2", 100L, "ops-2", now + 200L);
        blocklistService.cleanupExpiredAt(now + 350L);
        blocklistService.block(domain, "block-3", null, "ops-3", now + 400L);

        List<StatusTransition> chain = blocklistService.statusChain(domain);
        assertEquals(5, chain.size());
        assertTransition(chain.get(0), "BLOCK", null, BlockStatus.BLOCKED, "ops-1");
        assertTransition(chain.get(1), "EXPIRE", BlockStatus.BLOCKED, BlockStatus.EXPIRED, "system");
        assertTransition(chain.get(2), "REBLOCK", BlockStatus.EXPIRED, BlockStatus.BLOCKED, "ops-2");
        assertTransition(chain.get(3), "EXPIRE", BlockStatus.BLOCKED, BlockStatus.EXPIRED, "system");
        assertTransition(chain.get(4), "REBLOCK", BlockStatus.EXPIRED, BlockStatus.BLOCKED, "ops-3");
        assertEquals("block-1", chain.get(0).reason());
        assertEquals("block-3", chain.get(4).reason());
        assertTrue(blocklistService.isBlockedAt(domain, now + 500L));
    }

    @Test
    void firstTransitionHasNullPreviousStatus() {
        String domain = "chain-first.com";
        blocklistService.block(domain, "first", null, "ops", 50_000_000L);
        StatusTransition first = blocklistService.statusChain(domain).get(0);
        assertNull(first.fromStatus());
        assertEquals(BlockStatus.BLOCKED, first.toStatus());
    }

    private void assertTransition(StatusTransition transition, String action,
                                  BlockStatus from, BlockStatus to, String operator) {
        assertEquals(action, transition.action());
        assertEquals(from, transition.fromStatus());
        assertEquals(to, transition.toStatus());
        assertEquals(operator, transition.operator());
    }
}
