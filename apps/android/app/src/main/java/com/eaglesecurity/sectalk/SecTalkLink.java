package com.eaglesecurity.sectalk;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;

final class SecTalkLink {
    private static final List<String> EXACT_PATHS = Arrays.asList(
            "/", "/auth/confirm", "/auth/workspace-sso", "/auth/scim-claim", "/invite",
            "/room-guest", "/meeting-guest", "/shared-file");

    private SecTalkLink() {}

    static boolean isAllowed(String rawUrl, String launchUrl) {
        if (rawUrl == null) return false;
        try {
            URI link = new URI(rawUrl);
            String host = URI.create(launchUrl).getHost();
            String authority = link.getRawAuthority();
            if (!"https".equalsIgnoreCase(link.getScheme()) || authority == null
                    || !(host.equalsIgnoreCase(authority) || (host + ":443").equalsIgnoreCase(authority))) {
                return false;
            }

            String path = link.getRawPath();
            if (path.isEmpty()) return true;
            return EXACT_PATHS.contains(path)
                    || path.matches("/workspace-file/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+");
        } catch (URISyntaxException invalidUrl) {
            return false;
        }
    }
}
