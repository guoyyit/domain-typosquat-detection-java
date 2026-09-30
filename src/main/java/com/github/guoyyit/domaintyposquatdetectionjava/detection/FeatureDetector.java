package com.github.guoyyit.domaintyposquatdetectionjava.detection;

import com.github.guoyyit.domaintyposquatdetectionjava.model.HitFeature;

import java.util.Optional;

/**
 * 单一仿冒特征检测器。每个检测器只产生至多一条命中。
 */
public interface FeatureDetector {

    /**
     * @return 命中特征；未命中返回 empty
     */
    Optional<HitFeature> detect(DetectionContext context);
}
