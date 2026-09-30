package com.github.guoyyit.domaintyposquatdetectionjava.detection;

import org.springframework.stereotype.Component;

import java.net.IDN;

/**
 * 域名归一化：去除协议前缀、端口、用户信息、路径，小写化，去尾点，
 * Unicode 域名经 IDN 转换为 ASCII。相同输入必得相同输出。
 */
@Component
public class DomainNormalizer {

    /**
     * @return 归一化后的 ASCII 域名；输入为空或非法时抛出 IllegalArgumentException
     */
    public String normalize(String input) {
        if (input == null) {
            throw new IllegalArgumentException("domain must not be null");
        }
        String host = input.trim();
        if (host.isEmpty()) {
            throw new IllegalArgumentException("domain must not be blank");
        }

        int schemeAt = host.indexOf("://");
        if (schemeAt >= 0) {
            String scheme = host.substring(0, schemeAt).toLowerCase(java.util.Locale.ROOT);
            if (!scheme.matches("[a-z][a-z0-9+.-]*")) {
                throw new IllegalArgumentException("invalid scheme: " + scheme);
            }
            host = host.substring(schemeAt + 3);
        }
        host = stripAuthorityPrefix(host);
        host = stripPortAndPath(host);

        while (host.endsWith(".")) {
            host = host.substring(0, host.length() - 1);
        }
        String[] labels = host.split("\\.", -1);
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < labels.length; i++) {
            if (i > 0) {
                result.append('.');
            }
            result.append(normalizeLabel(labels[i]));
        }
        if (result.length() == 0) {
            throw new IllegalArgumentException("domain must not be blank");
        }
        return result.toString();
    }

    private String stripAuthorityPrefix(String host) {
        if (host.startsWith("//")) {
            host = host.substring(2);
        }
        int at = host.indexOf('@');
        if (at >= 0) {
            host = host.substring(at + 1);
        }
        return host;
    }

    private String stripPortAndPath(String host) {
        int slash = host.indexOf('/');
        if (slash >= 0) {
            host = host.substring(0, slash);
        }
        int colon = host.indexOf(':');
        if (colon >= 0) {
            String port = host.substring(colon + 1);
            if (!port.matches("\\d{1,5}")) {
                throw new IllegalArgumentException("invalid port: " + port);
            }
            host = host.substring(0, colon);
        }
        int question = host.indexOf('?');
        if (question >= 0) {
            host = host.substring(0, question);
        }
        return host;
    }

    private String normalizeLabel(String label) {
        if (label.isEmpty()) {
            throw new IllegalArgumentException("empty label in domain");
        }
        try {
            String ascii = IDN.toASCII(label, IDN.ALLOW_UNASSIGNED)
                    .toLowerCase(java.util.Locale.ROOT);
            if (ascii.isEmpty()) {
                throw new IllegalArgumentException("empty label in domain");
            }
            for (int i = 0; i < ascii.length(); i++) {
                char c = ascii.charAt(i);
                boolean valid = c == '-' || c == '.'
                        || (c >= 'a' && c <= 'z')
                        || (c >= '0' && c <= '9');
                if (!valid) {
                    throw new IllegalArgumentException("invalid character in label: " + label);
                }
            }
            return ascii;
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("invalid domain label: " + label, e);
        }
    }
}
