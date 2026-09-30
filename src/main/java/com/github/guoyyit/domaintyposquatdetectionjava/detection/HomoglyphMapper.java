package com.github.guoyyit.domaintyposquatdetectionjava.detection;

import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * 同形字符归并：将视觉相似字符映射为同一骨架，再与受保护域名比较。
 */
@Component
public class HomoglyphMapper {

    private static final Map<Character, Character> ASCII_EQUIVALENTS = new HashMap<>();

    static {
        // 西里尔字母 -> 视觉相同的拉丁字母
        map('а', 'a'); map('е', 'e'); map('о', 'o'); map('р', 'p'); map('с', 'c');
        map('у', 'y'); map('х', 'x'); map('ѕ', 's'); map('і', 'i'); map('ј', 'j');
        map('ԛ', 'q'); map('ԝ', 'w'); map('к', 'k'); map('м', 'm'); map('т', 't');
        map('н', 'h'); map('в', 'b'); map('г', 'r'); map('ь', 'b'); map('ԁ', 'd');
        map('ѕ', 's'); map('ӏ', 'l'); map('ґ', 'r'); map('ԛ', 'q');
        // 希腊字母 -> 视觉相近的拉丁字母
        map('ο', 'o'); map('ε', 'e'); map('α', 'a'); map('ρ', 'p'); map('κ', 'k');
        map('ν', 'v'); map('υ', 'u'); map('τ', 't'); map('χ', 'x'); map('ζ', 'z');
        map('ι', 'i'); map('ο', 'o'); map('Α', 'a'); map('Β', 'b'); map('Ε', 'e');
        // 数字/符号变体
        map('0', 'o'); map('1', 'l'); map('3', 'e'); map('4', 'a'); map('5', 's');
        map('$', 's'); map('@', 'a');
        // 常见拉丁同形全角/连字
        map('ä', 'a'); map('ö', 'o'); map('ü', 'u');
    }

    private static void map(char from, char to) {
        ASCII_EQUIVALENTS.put(from, to);
    }

    /**
     * @return 归并后的 ASCII 骨架
     */
    public String skeleton(String input) {
        if (input == null) {
            return null;
        }
        StringBuilder builder = new StringBuilder(input.length());
        for (int i = 0; i < input.length(); i++) {
            char ch = input.charAt(i);
            Character mapped = ASCII_EQUIVALENTS.get(ch);
            if (mapped != null) {
                builder.append(mapped);
            } else if (ch < 128) {
                builder.append(Character.toLowerCase(ch));
            }
        }
        return builder.toString();
    }

    /**
     * 输入中是否存在同形替换字符。
     */
    public boolean containsHomoglyph(String input) {
        if (input == null) {
            return false;
        }
        for (int i = 0; i < input.length(); i++) {
            if (ASCII_EQUIVALENTS.containsKey(input.charAt(i))) {
                return true;
            }
        }
        return false;
    }
}
