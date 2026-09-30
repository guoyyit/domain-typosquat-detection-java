package com.github.guoyyit.domaintyposquatdetectionjava.detection;

import org.springframework.stereotype.Component;

import java.net.IDN;
import java.util.HashMap;
import java.util.Map;

/**
 * 将常见视觉同形字符（西里尔 а/е/о、希腊 ο 等）映射为 ASCII 骨架，
 * 用于检测同形字符替换。映射表固定，保证可复现。
 */
@Component
public class ConfusableMapper {

    private static final Map<Character, Character> CONFUSABLES;

    static {
        Map<Character, Character> map = new HashMap<>();
        // 西里尔字母（小写）
        map.put('а', 'a');
        map.put('е', 'e');
        map.put('о', 'o');
        map.put('р', 'p');
        map.put('с', 'c');
        map.put('у', 'y');
        map.put('х', 'x');
        map.put('ѕ', 's');
        map.put('і', 'i');
        map.put('ј', 'j');
        map.put('ԁ', 'd');
        map.put('ɡ', 'g');
        // 西里尔字母（大写）
        map.put('А', 'a');
        map.put('В', 'b');
        map.put('Е', 'e');
        map.put('К', 'k');
        map.put('М', 'm');
        map.put('Н', 'h');
        map.put('О', 'o');
        map.put('Р', 'p');
        map.put('С', 'c');
        map.put('Т', 't');
        map.put('Х', 'x');
        map.put('У', 'y');
        // 希腊字母
        map.put('ο', 'o');
        map.put('Ο', 'o');
        map.put('α', 'a');
        map.put('Α', 'a');
        map.put('ε', 'e');
        map.put('Ε', 'e');
        map.put('ρ', 'p');
        map.put('Ρ', 'p');
        map.put('υ', 'u');
        map.put('ι', 'i');
        map.put('κ', 'k');
        map.put('μ', 'm');
        map.put('τ', 't');
        map.put('ν', 'v');
        map.put('η', 'n');
        map.put('ο', 'o');
        // 拉丁补充（重音字母）
        map.put('à', 'a');
        map.put('á', 'a');
        map.put('â', 'a');
        map.put('ã', 'a');
        map.put('ä', 'a');
        map.put('å', 'a');
        map.put('ç', 'c');
        map.put('è', 'e');
        map.put('é', 'e');
        map.put('ê', 'e');
        map.put('ë', 'e');
        map.put('ì', 'i');
        map.put('í', 'i');
        map.put('î', 'i');
        map.put('ï', 'i');
        map.put('ñ', 'n');
        map.put('ò', 'o');
        map.put('ó', 'o');
        map.put('ô', 'o');
        map.put('õ', 'o');
        map.put('ö', 'o');
        map.put('ù', 'u');
        map.put('ú', 'u');
        map.put('û', 'u');
        map.put('ü', 'u');
        map.put('ý', 'y');
        map.put('ÿ', 'y');
        // 全角拉丁
        map.put('Ａ', 'a');
        map.put('Ｂ', 'b');
        map.put('Ｃ', 'c');
        map.put('Ｄ', 'd');
        map.put('Ｅ', 'e');
        map.put('Ｆ', 'f');
        map.put('Ｇ', 'g');
        map.put('Ｈ', 'h');
        map.put('Ｉ', 'i');
        map.put('Ｊ', 'j');
        map.put('Ｋ', 'k');
        map.put('Ｌ', 'l');
        map.put('Ｍ', 'm');
        map.put('Ｎ', 'n');
        map.put('Ｏ', 'o');
        map.put('Ｐ', 'p');
        map.put('Ｑ', 'q');
        map.put('Ｒ', 'r');
        map.put('Ｓ', 's');
        map.put('Ｔ', 't');
        map.put('Ｕ', 'u');
        map.put('Ｖ', 'v');
        map.put('Ｗ', 'w');
        map.put('Ｘ', 'x');
        map.put('Ｙ', 'y');
        map.put('Ｚ', 'z');
        CONFUSABLES = Map.copyOf(map);
    }

    /**
     * @return ASCII 骨架字符串；点号、ASCII 字母数字原样保留，同形字符按固定表折叠
     */
    public String skeleton(String asciiOrUnicodeDomain) {
        String unicode = toUnicodeLabels(asciiOrUnicodeDomain);
        StringBuilder sb = new StringBuilder(unicode.length());
        for (int i = 0; i < unicode.length(); i++) {
            char c = unicode.charAt(i);
            if (c == '.') {
                sb.append('.');
            } else if (c >= 'a' && c <= 'z') {
                sb.append(c);
            } else if (c >= 'A' && c <= 'Z') {
                sb.append((char) (c - 'A' + 'a'));
            } else if (c >= '0' && c <= '9') {
                sb.append(c);
            } else {
                Character mapped = CONFUSABLES.get(c);
                if (mapped != null) {
                    sb.append(mapped);
                }
            }
        }
        return sb.toString();
    }

    /**
     * 归一化后的 ASCII 域名是否包含非 ASCII 的同形字符
     * （IDN 后表现为 xn-- 标签）。
     */
    public boolean containsHomoglyph(String normalizedAsciiDomain) {
        if (normalizedAsciiDomain == null) {
            return false;
        }
        for (String label : normalizedAsciiDomain.split("\\.", -1)) {
            if (label.startsWith("xn--")) {
                return true;
            }
        }
        return false;
    }

    /** 将可能含 punycode 标签的域名转回 Unicode，便于按码点做同形映射。 */
    private String toUnicodeLabels(String domain) {
        if (domain == null) {
            return "";
        }
        String[] labels = domain.split("\\.", -1);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < labels.length; i++) {
            if (i > 0) {
                sb.append('.');
            }
            sb.append(IDN.toUnicode(labels[i], IDN.ALLOW_UNASSIGNED));
        }
        return sb.toString();
    }
}
