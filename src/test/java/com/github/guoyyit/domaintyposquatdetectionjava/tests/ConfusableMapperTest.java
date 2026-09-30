package com.github.guoyyit.domaintyposquatdetectionjava.tests;

import com.github.guoyyit.domaintyposquatdetectionjava.detection.ConfusableMapper;
import com.github.guoyyit.domaintyposquatdetectionjava.detection.DomainNormalizer;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConfusableMapperTest {

    private final ConfusableMapper mapper = new ConfusableMapper();
    private final DomainNormalizer normalizer = new DomainNormalizer();

    @Test
    void cyrillicLookalikeFoldsToAscii() {
        // а/р 为西里尔字母，视觉上像 a/p
        String ascii = normalizer.normalize("раypal.com");
        assertTrue(mapper.containsHomoglyph(ascii));
        assertEquals("paypal.com", mapper.skeleton(ascii));
    }

    @Test
    void greekOmicronFolds() {
        String ascii = normalizer.normalize("gοοgle.com");
        assertTrue(mapper.containsHomoglyph(ascii));
        assertEquals("google.com", mapper.skeleton(ascii));
    }

    @Test
    void plainAsciiIsNotHomoglyphAndStable() {
        String ascii = normalizer.normalize("paypal.com");
        assertFalse(mapper.containsHomoglyph(ascii));
        assertEquals("paypal.com", mapper.skeleton(ascii));
    }

    @Test
    void skeletonIsDeterministic() {
        String once = mapper.skeleton(normalizer.normalize("раypal.com"));
        String twice = mapper.skeleton(normalizer.normalize("раypal.com."));
        assertEquals(once, twice);
    }
}
