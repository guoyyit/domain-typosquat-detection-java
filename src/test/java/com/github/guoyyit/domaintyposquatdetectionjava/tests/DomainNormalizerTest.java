package com.github.guoyyit.domaintyposquatdetectionjava.tests;

import com.github.guoyyit.domaintyposquatdetectionjava.normalize.DomainNormalizer;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class DomainNormalizerTest {

    private final DomainNormalizer normalizer = new DomainNormalizer();

    @Test
    void normalizesCaseTrailingDotPortAndScheme() {
        String expected = "example.com";
        assertEquals(expected, normalizer.normalize("EXAMPLE.COM"));
        assertEquals(expected, normalizer.normalize("example.com."));
        assertEquals(expected, normalizer.normalize("https://example.com:443"));
        assertEquals("www.example.com", normalizer.normalize("http://WWW.Example.COM:8080/path?x=1"));
        assertEquals(expected, normalizer.normalize("  example.com  "));
    }

    @Test
    void convertsUnicodeToAsciiViaIdn() {
        String ascii = normalizer.normalize("例え.テスト");
        assertEquals("xn--r8jz45g.xn--zckzah", ascii);
        assertEquals(ascii, normalizer.normalize("xn--r8jz45g.xn--zckzah"));
    }

    @Test
    void rejectsInvalidDomains() {
        assertNull(normalizer.normalize(null));
        assertNull(normalizer.normalize(""));
        assertNull(normalizer.normalize("   "));
        assertNull(normalizer.normalize("bad..com"));
    }

    @Test
    void extractsRegistrableDomainAndLabels() {
        assertEquals("example.com", normalizer.registrableDomain("login.example.com"));
        assertEquals("example.com", normalizer.registrableDomain("example.com"));
        assertArrayEquals(new String[]{"login", "example", "com"},
                normalizer.labels("login.example.com"));
    }
}
