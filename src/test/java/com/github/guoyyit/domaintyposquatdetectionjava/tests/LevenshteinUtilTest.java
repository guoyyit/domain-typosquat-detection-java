package com.github.guoyyit.domaintyposquatdetectionjava.tests;

import com.github.guoyyit.domaintyposquatdetectionjava.detection.LevenshteinUtil;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LevenshteinUtilTest {

    @Test
    void computesKnownDistances() {
        assertEquals(0, LevenshteinUtil.distance("abc", "abc"));
        assertEquals(1, LevenshteinUtil.distance("paypal.com", "paypai.com"));
        assertEquals(3, LevenshteinUtil.distance("kitten", "sitting"));
        assertEquals(2, LevenshteinUtil.distance("google.com", "g00gle.com"));
    }

    @Test
    void symmetricAndDeterministic() {
        assertEquals(LevenshteinUtil.distance("paypal.com", "paypai.com"),
                LevenshteinUtil.distance("paypai.com", "paypal.com"));
        int first = LevenshteinUtil.distance("google.com", "g00gle.com");
        int second = LevenshteinUtil.distance("google.com", "g00gle.com");
        assertEquals(first, second);
    }

    @Test
    void insertDeleteOnlyCases() {
        assertTrue(LevenshteinUtil.insertDeleteWithin("paypal", "paypall", 1));
        assertTrue(LevenshteinUtil.insertDeleteWithin("paypal", "paypa", 1));
        assertTrue(LevenshteinUtil.insertDeleteWithin("abc", "aXbYc", 2));
        assertFalse(LevenshteinUtil.insertDeleteWithin("paypal", "payp0l", 1));
        assertFalse(LevenshteinUtil.insertDeleteWithin("abc", "xyz", 2));
    }

    @Test
    void identicalStringsAreInsertDeleteZero() {
        assertTrue(LevenshteinUtil.insertDeleteWithin("abc", "abc", 0));
    }
}
