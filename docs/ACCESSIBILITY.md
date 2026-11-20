# Accessibility verification

The v6 browser fixture creates two disposable accounts and runs axe-core with the WCAG 2.0, 2.1 and 2.2 A and AA tags. It exercises public sign-in and recovery, keyboard message and call controls, authenticated feature navigation, and mobile status and notification views. Chromium's accessibility tree is checked for the message log, labeled composer and attachment actions, and a live incoming-call status. CI builds the same application against a fresh local Supabase stack.

Run `node tests/accessibility.e2e.mjs` against a disposable loopback build with the existing `SECTALK_STORAGE_TEST_*` variables. Provide the installed Playwright module in `SECTALK_PLAYWRIGHT_MODULE` and the pinned axe browser bundle path in `SECTALK_AXE_SCRIPT`. Set `SECTALK_TEST_BROWSER` when using a locally installed Edge executable.

Manual release acceptance includes a supported screen reader on desktop and mobile, 200% text zoom, visible and unobscured focus, and full keyboard navigation through onboarding, chat actions, call and meeting controls, reporting, and billing. Confirm that live messages, incoming calls and disconnects, asynchronous errors, and successful actions are announced at appropriate priority. Automated checks alone do not establish full WCAG conformance. [WCAG 2.2](https://www.w3.org/TR/WCAG22/)
