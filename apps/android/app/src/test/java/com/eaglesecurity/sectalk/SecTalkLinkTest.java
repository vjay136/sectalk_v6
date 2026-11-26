package com.eaglesecurity.sectalk;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public final class SecTalkLinkTest {
    private static final String ORIGIN = "https://sectalk-v6-pilot.vercel.app";

    @Test
    public void acceptsOnlySupportedCanonicalLinks() {
        for (String path : new String[] { "", "/", "/auth/confirm?code=test#fragment",
                "/auth/workspace-sso", "/auth/scim-claim", "/invite", "/room-guest", "/meeting-guest",
                "/shared-file", "/workspace-file/example-workspace/example-file" }) {
            assertTrue(path, SecTalkLink.isAllowed(ORIGIN + path, ORIGIN + "/"));
        }
    }

    @Test
    public void keepsOtherOriginsAndNonAppRoutesInBrowser() {
        for (String url : new String[] { null, "not a URL", "https://example.org/invite",
                "http://sectalk-v6-pilot.vercel.app/invite", ORIGIN + ":8443/invite",
                ORIGIN + "/about", ORIGIN + "/api/health", ORIGIN + "/workspace-file/example" }) {
            assertFalse(url, SecTalkLink.isAllowed(url, ORIGIN + "/"));
        }
    }
}
