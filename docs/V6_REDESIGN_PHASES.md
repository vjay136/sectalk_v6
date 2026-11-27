# SecTalk v6 redesign phases

| Phase | Scope | Acceptance |
| --- | --- | --- |
| Member interface | Inbox, conversation controls, Calls, Safety and More on desktop and Android | Fit narrow screens, keep primary actions visible, and preserve advanced controls in context |
| Discovery and availability | Single-letter search, online browsing, category filters and contact presence | Verify opted-in results and live updates with separate accounts, including hidden and blocked accounts |
| Global search | A shortcut from Inbox and role-scoped search across conversations, workspaces, files, people and schedules | Verify that visible content opens correctly and unauthorized content stays out of results |
| Direct calls | Caller ringback, receiving ringtone, compact call controls, microphone noise reduction, setup recovery and relay diagnostics | Verify audio and video with dummy accounts. Check hosted relay readiness and cross-network behavior separately |
| Admin operations | Activity, safety and storage dashboards alongside report and account workflows | Verify scoped aggregates, role denial, recent authenticator proof, and navigation into existing authorized actions |
| Release | Private Admin deployment, public Web deployment and signed Android compatibility | Verify exact release revisions and run the applicable browser and Android checks |

Member sign-up and sign-in continue to use email and password. Admin access requires the SecTalk authenticator. Preserve previously enrolled security factors.

## Verification record

| Phase | Evidence |
| --- | --- |
| Member interface | Edge covered the messenger shell at 320, 360, 390 and 1440 px, including chat controls, message send and persistence, Calls, Safety and More. A three-account run opened 15 top-level tabs. |
| Discovery and availability | Three accounts exercised one-letter search, categories, online filtering, opt-out, contact requests and automatic offline updates. Separate database checks covered privacy and blocked accounts. |
| Global search | Three accounts exercised direct-message and exact-handle search, opening a matching room, mobile filters at 320 px and denial of access to private content. SQL coverage includes files. |
| Direct calls | Both parties rang and stopped ringing on answer. Audio and video sent media in both directions over direct browser connections and through a local TURN relay. Dummy-account tests also toggled the sending microphone's reported noise reduction setting in audio and video calls. Hosted cross-network calls and Android background ringing remain open. |
| Admin operations | Browser checks exercised first-time QR enrollment, denied ordinary-account access, opened the 234-entry feature inventory and navigated from aggregate safety metrics into moderation. Activity and storage totals come from Supabase. |
| Release verification | The registry reports 234 completed Free-tier entries and five deferred entries. The automated suite passed 118 tests on Windows. Docker passed two Linux-specific cases that Windows skipped. The hosted enterprise identity-provider fixture remains skipped. These checks do not establish individual live Web and Android verification for every feature. |

## Screenshot findings

The desktop and phone call captures show the call stuck connecting until timeout, and the thread status can disagree with the other device. On mobile, the contact name wraps letter by letter because the header prioritizes secondary icons. The timer and formatting controls take space away from the message list. Calls and Safety fill multiple rows with tabs, and call-row buttons compress names and dates. The More menu overlays the workspace without a clear heading or close control. Find Friends gives filters and suggested categories more space than results. The inbox needs a clearer hierarchy for requests, search, and recent conversations.
