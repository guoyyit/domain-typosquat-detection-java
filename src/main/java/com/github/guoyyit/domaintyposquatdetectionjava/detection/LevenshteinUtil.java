package com.github.guoyyit.domaintyposquatdetectionjava.detection;

/**
 * 确定性 Levenshtein 编辑距离，及“仅插入/删除可达”判定。
 */
public final class LevenshteinUtil {

    private LevenshteinUtil() {
    }

    public static int distance(String a, String b) {
        if (a.equals(b)) {
            return 0;
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
                current[j] = Math.min(Math.min(current[j - 1] + 1, previous[j] + 1),
                        previous[j - 1] + cost);
            }
            int[] tmp = previous;
            previous = current;
            current = tmp;
        }
        return previous[b.length()];
    }

    /**
     * 两个字符串是否可在 maxDistance 次以内仅通过插入/删除互相转换
     * （长度差即所需次数，短串须为长串的子序列）。
     */
    public static boolean insertDeleteWithin(String a, String b, int maxDistance) {
        int lengthDiff = Math.abs(a.length() - b.length());
        if (lengthDiff == 0) {
            return a.equals(b);
        }
        if (lengthDiff > maxDistance) {
            return false;
        }
        String shorter = a.length() <= b.length() ? a : b;
        String longer = a.length() <= b.length() ? b : a;
        int si = 0;
        for (int li = 0; li < longer.length() && si < shorter.length(); li++) {
            if (longer.charAt(li) == shorter.charAt(si)) {
                si++;
            }
        }
        return si == shorter.length();
    }
}
