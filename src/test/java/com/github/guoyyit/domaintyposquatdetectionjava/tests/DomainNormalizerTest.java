package com.github.guoyyit.domaintyposquatdetectionjava.tests;

import com.github.guoyyit.domaintyposquatdetectionjava.detection.DomainNormalizer;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DomainNormalizerTest {

    private final DomainNormalizer normalizer = new DomainNormalizer();

    @Test
    void lowercasesTrimsAndRemovesTrailingDot() {
        assertEquals("example.com", normalizer.normalize("  EXAMPLE.COM.  "));
    }

    @Test
    void stripsSchemePortAndPath() {
        assertEquals("example.com", normalizer.normalize("https://example.com:443/a/b?x=1"));
        assertEquals("example.com", normalizer.normalize("http://example.com:8080"));
        assertEquals("example.com", normalizer.normalize("ftp://user@example.com/path"));
    }

    @Test
    void protocolSchemalessAuthorityAlsoStripped() {
        assertEquals("example.com", normalizer.normalize("//user:pass@example.com:8443/x"));
        assertEquals("example.com", normalizer.normalize("example.com:443"));
    }

    @Test
    void unicodeBecomesDeterministicAscii() {
        String expected = normalizer.normalize("xn--e1aybc.xn--p1ai");
        assertEquals(expected, normalizer.normalize("тест.рф"));
        assertEquals(expected, normalizer.normalize("ТЕСТ.РФ."));
        assertEquals(expected, normalizer.normalize("https://тест.рф:443/"));
    }

    @Test
    void mixedCaseCyrillicIsStableAcrossForms() {
        assertEquals(normalizer.normalize("раypal.com"), normalizer.normalize("раypal.com."));
    }

    @Test
    void blankAndInvalidInputsRejected() {
        assertThrows(IllegalArgumentException.class, () -> normalizer.normalize("   "));
        assertThrows(IllegalArgumentException.class, () -> normalizer.normalize(null));
        assertThrows(IllegalArgumentException.class, () -> normalizer.normalize("exa mple.com"));
        assertThrows(IllegalArgumentException.class, () -> normalizer.normalize("not:// ok.com"));
    }
}
