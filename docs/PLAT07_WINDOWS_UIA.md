# Windows accessibility acceptance

A headed Microsoft Edge session on Windows exercised the loopback 3581 app with disposable accounts. Browser automation prepared each real product state. A Windows UI Automation client then inspected the native controls exposed by Edge.

| Flow | Observed in the Windows UI Automation tree |
| --- | --- |
| Sign-in and recovery | Sign-in and reset headings, named email and password inputs on sign-in, recovery email input, and a back-to-sign-in action. |
| Account registration | Named email, password and password confirmation inputs, verification explanation, and the create-account action. |
| Direct chat | Named Messages log containing a newly sent synthetic message, named composer, file attachment and message actions, and a disabled Send message button after submission. |
| Incoming audio call | Audio call region, Incoming call within a status control, and named Answer, Decline and Call menu controls. A second synthetic account placed the call. |
| Safety | Safety center heading, report and account-notice selectors, named room and channel report regions, and empty states. |
| Profile | Profile heading, named Display name input, disabled Handle field, Save profile and photo upload, and visible security and privacy selectors. |

The Playwright and axe suite covers keyboard flows and WCAG rules. This Windows inspection adds native role, name and state evidence. The desktop client reported the Edge address bar as focused during inspection. Actual screen-reader evidence came from the separate NVDA run below.

A separate Edge run verified keyboard focus entering personal export and deletion forms and returning to the invoking button on cancellation. The same run checked the public privacy notice on mobile. The brand link now exposes the same text visually and to assistive technology.

A follow-up on Windows 11 25H2 prepared a dedicated Edge window on loopback with synthetic accounts and started built-in Narrator. Windows blocked the automation helper from inspecting the Narrator window because it runs at a higher integrity level. Edge foreground activation also failed while Narrator was active. Neither speech output nor scan-mode navigation was captured in this attempt. [Microsoft Narrator Speech Recap](https://support.microsoft.com/en-us/accessibility/windows/narrator/chapter-2-narrator-basics)

Portable NVDA 2026.3.1 ran with a separate local QA profile and Speech Viewer after Narrator exited. Actual speech identified the email edit field, the message composer, the export button, the focused password verification field, and the Safety and Billing controls. A new synthetic message appeared in Speech Viewer. The incoming-call panel originally rendered without a spoken alert. After a persistent alert was added, a fresh incoming audio call announced its type and synthetic caller name. The last verification began with no active incoming alert. The portable screen reader and browser fixture were closed after testing. [NVDA Speech Viewer](https://api.nvaccess.org/documentation/userGuide.html#SpeechViewer)

The expanded Edge suite verified keyboard selection and current-page state across the primary sections, including both task navigation levels. An incoming call updated the announcement already mounted on the page, then cleared it after declining. An equivalent call during an enabled Quiet Hours override produced neither an on-screen call panel nor an announcement. The axe checks passed for the tested desktop and mobile views.

[Microsoft Edge and Windows UI Automation](https://learn.microsoft.com/en-us/microsoft-edge/accessibility/)
