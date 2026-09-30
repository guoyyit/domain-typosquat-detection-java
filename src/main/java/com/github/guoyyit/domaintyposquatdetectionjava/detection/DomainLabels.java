package com.github.guoyyit.domaintyposquatdetectionjava.detection;

/**
 * 归一化域名的标签结构工具。
 * registrable = 最左标签 + "." + 末级标签（两标签近似），
 * 不引入外部公共后缀列表，保证纯函数与确定性。
 */
public final class DomainLabels {

    private DomainLabels() {
    }

    public static String[] labels(String normalizedDomain) {
        return normalizedDomain.split("\\.", -1);
    }

    /** 末级标签（顶级域）。 */
    public static String tld(String normalizedDomain) {
        String[] labels = labels(normalizedDomain);
        return labels[labels.length - 1];
    }

    /** 最左标签。 */
    public static String leftmost(String normalizedDomain) {
        return labels(normalizedDomain)[0];
    }

    /**
     * 可注册主体：至少两个标签时取“最左标签.顶级域”；
     * 单标签主机名原样返回。
     */
    public static String registrable(String normalizedDomain) {
        String[] labels = labels(normalizedDomain);
        if (labels.length <= 2) {
            return normalizedDomain;
        }
        return labels[0] + "." + labels[labels.length - 1];
    }

    /** 去掉最左标签后的剩余部分；单标签返回空串。 */
    public static String parent(String normalizedDomain) {
        int dot = normalizedDomain.indexOf('.');
        return dot < 0 ? "" : normalizedDomain.substring(dot + 1);
    }
}
