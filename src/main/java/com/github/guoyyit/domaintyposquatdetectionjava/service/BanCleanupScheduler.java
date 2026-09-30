package com.github.guoyyit.domaintyposquatdetectionjava.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * 周期性把已过期的 ACTIVE 封禁回收为 EXPIRED；
 * 查询路径上另有惰性回收，保证双重可靠。
 */
@Component
public class BanCleanupScheduler {

    private static final Logger log = LoggerFactory.getLogger(BanCleanupScheduler.class);

    private final EnforcementService enforcementService;

    public BanCleanupScheduler(EnforcementService enforcementService) {
        this.enforcementService = enforcementService;
    }

    @Scheduled(fixedDelayString = "${typosquat.detection.ban.cleanup-interval-millis:60000}")
    public void cleanup() {
        int expired = enforcementService.cleanupExpired();
        if (expired > 0) {
            log.info("expired {} ban record(s)", expired);
        }
    }
}
