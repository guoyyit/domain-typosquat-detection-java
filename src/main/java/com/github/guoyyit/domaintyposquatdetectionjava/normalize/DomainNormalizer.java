package com.github.guoyyit.domaintyposquatdetectionjava.normalize;

import org.springframework.stereotype.Component;

import java.net.IDN;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Locale;

/**
 * 域名归一化：协议、端口、大小写、尾点差异被消除，Unicode 经 IDN 转为 ASCII。
 */
@Component
public class DomainNormalizer {

    /**
     * @return 归一化主机名；输入非法时返回 {@code null}
     */
    public String normalize(String raw) {
        if (raw == null) {
            return null;
        }
        String value = raw.trim().toLowerCase(Locale.ROOT);
        if (value.isEmpty()) {
            return null;
        }

        String host = stripSchemeAndPath(value);
        if (host == null || host.isEmpty()) {
            return null;
        }
        if (host.startsWith("[") && host.endsWith("]")) {
            return null;
        }
        int userAt = host.lastIndexOf('@');
        if (userAt >= 0) {
            host = host.substring(userAt + 1);
        }
        int colon = host.lastIndexOf(':');
        if (colon >= 0) {
            String portPart = host.substring(colon + 1);
            if (portPart.matches("\\d*")) {
                host = host.substring(0, colon);
            }
        }
        if (host.endsWith(".")) {
            host = host.substring(0, host.length() - 1);
        }
        if (host.isEmpty() || host.contains("..")) {
            return null;
        }
        return toAscii(host);
    }

    /**
     * 与 {@link #normalize(String)} 相同的清洗规则，但保留 Unicode 标签形式
     * （对 punycode 做 IDN 反向转换），用于同形字符视觉比对。
     *
     * @return Unicode 形式主机名；输入非法时返回 {@code null}
     */
    public String normalizeUnicode(String raw) {
        String ascii = normalize(raw);
        if (ascii == null) {
            return null;
        }
        String[] labels = labels(ascii);
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < labels.length; i++) {
            if (i > 0) {
                builder.append('.');
            }
            try {
                builder.append(IDN.toUnicode(labels[i], IDN.ALLOW_UNASSIGNED));
            } catch (IllegalArgumentException ex) {
                builder.append(labels[i]);
            }
        }
        return builder.toString();
    }

    /**
     * 取可注册主域（最后两个标签）。
     */
    public String registrableDomain(String normalized) {
        if (normalized == null) {
            return null;
        }
        String[] parts = labels(normalized);
        if (parts.length == 0) {
            return null;
        }
        return parts.length == 1 ? parts[0] : parts[parts.length - 2] + "." + parts[parts.length - 1];
    }

    /**
     * 以点拆分标签。
     */
    public String[] labels(String normalized) {
        if (normalized == null || normalized.isEmpty()) {
            return new String[0];
        }
        return normalized.split("\\.");
    }

    private String stripSchemeAndPath(String value) {
        String host = value;
        if (host.contains("://")) {
            try {
                return new URL("http://" + host.substring(host.indexOf("://") + 3)).getHost();
            } catch (MalformedURLException ignored) {
                return null;
            }
        }
        int slash = host.indexOf('/');
        if (slash >= 0) {
            host = host.substring(0, slash);
        }
        int question = host.indexOf('?');
        if (question >= 0) {
            host = host.substring(0, question);
        }
        return host;
    }

    private String toAscii(String host) {
        String[] labels = labels(host);
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < labels.length; i++) {
            String label = labels[i];
            if (label.isEmpty()) {
                return null;
            }
            try {
                label = IDN.toASCII(label, IDN.ALLOW_UNASSIGNED);
            } catch (IllegalArgumentException ex) {
                return null;
            }
            if (i > 0) {
                builder.append('.');
            }
            builder.append(label);
        }
        return builder.toString();
    }
}
