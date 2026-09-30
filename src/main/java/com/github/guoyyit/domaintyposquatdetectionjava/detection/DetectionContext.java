package com.github.guoyyit.domaintyposquatdetectionjava.detection;

import com.github.guoyyit.domaintyposquatdetectionjava.config.DetectionProperties;
import com.github.guoyyit.domaintyposquatdetectionjava.model.ProtectedDomain;

import java.util.List;

/**
 * 单次检测的不可变输入上下文。
 */
public class DetectionContext {

    private final String input;
    private final String normalized;
    private final List<ProtectedDomain> protectedDomains;
    private final DetectionProperties properties;

    public DetectionContext(String input, String normalized,
                            List<ProtectedDomain> protectedDomains,
                            DetectionProperties properties) {
        this.input = input;
        this.normalized = normalized;
        this.protectedDomains = protectedDomains;
        this.properties = properties;
    }

    public String getInput() { return input; }
    public String getNormalized() { return normalized; }
    public List<ProtectedDomain> getProtectedDomains() { return protectedDomains; }
    public DetectionProperties getProperties() { return properties; }
}
