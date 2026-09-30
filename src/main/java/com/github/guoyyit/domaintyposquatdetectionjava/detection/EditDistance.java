package com.github.guoyyit.domaintyposquatdetectionjava.detection;

import org.springframework.stereotype.Component;

/**
 * Levenshtein 编辑距离与纯插入/删除判定，结果确定可复现。
 */
@Component
public class EditDistance {

    public int levenshtein(String a, String b) {
        if (a.equals(b)) {
            return 0;
        }
        if (a.isEmpty()) {
            return b.length();
        }
        if (b.isEmpty()) {
            return a.length();
        }
        int[] previous = new int[b.length() + 1];
        int[] current = new int[b.length() + 1];
        for (int j = 0; j <= b.length(); j++) {
            previous[j] = j;
        }
        for (int i = 1; i <= a.length(); i++) {
            current[0] = i;
            char ca = a.charAt(i - 1);
            for (int j = 1; j <= b.length(); j++) {
                int cost = ca == b.charAt(j - 1) ? 0 : 1;
                current[j] = Math.min(Math.min(current[j - 1] + 1, previous[j] + 1), previous[j - 1] + cost);
            }
            int[] swap = previous;
            previous = current;
            current = swap;
        }
        return previous[b.length()];
    }

    /**
     * 距离是否仅由插入/删除构成（无替换）。
     */
    public boolean isInsertionOrDeletion(String a, String b, int distance) {
        if (distance <= 0 || Math.abs(a.length() - b.length()) != distance) {
            return false;
        }
        String longer = a.length() >= b.length() ? a : b;
        String shorter = a.length() >= b.length() ? b : a;
        int li = 0;
        int si = 0;
        int skipped = 0;
        while (li < longer.length() && si < shorter.length()) {
            if (longer.charAt(li) == shorter.charAt(si)) {
                li++;
                si++;
            } else {
                skipped++;
                li++;
                if (skipped > distance) {
                    return false;
                }
            }
        }
        skipped += longer.length() - li;
        return skipped == distance && si == shorter.length();
    }
}
