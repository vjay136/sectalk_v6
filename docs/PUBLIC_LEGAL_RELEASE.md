# Public legal release configuration

The public Legal page links to Terms, Privacy and the unsigned DPA template. Terms and Privacy show explicit drafts until an operator configures a complete, approved and effective release. The DPA route remains a template for the applicable agreement.

Keep the approved documents and operator metadata with the release record. Set the server-side `SECTALK_PUBLIC_LEGAL_RELEASE` environment value to the exact approved JSON bundle when the operator authorizes publication. The existing site uses the release only when both documents are effective. Pages render supplied text literally.

| Field | Expected value |
| --- | --- |
| `operator.name` | Approved public operator name |
| `operator.supportEmail` or `operator.supportUrl` | Approved monitored public service email address or HTTPS contact form |
| `operator.privacyEmail` or `operator.privacyUrl` | Approved monitored public privacy email address or HTTPS contact form |
| `terms` and `privacy` | Each contains `status` equal to `"approved"`, a `version`, an `approvedOn` date, an `effectiveOn` date, and `sections` |
| Dates | Calendar dates in `YYYY-MM-DD` format. Approval must be on or before the effective date. The effective date must have arrived in UTC. |
| `sections` | An ordered array of 1–24 objects with a plain-text `title` and `text`. Blank lines can separate paragraphs. |

Choose one contact value per purpose. Contact form URLs use HTTPS and have no credentials, query parameters, or fragments. Verify that the service and privacy contacts are monitored before approving the release. SecTalk’s vulnerability disclosure form serves its separate security queue.

The bundle is limited to 32,000 UTF-8 bytes. Leave the variable unset in environments that should display drafts. Invalid or incomplete data leaves both public documents in draft and hides operator metadata. The runtime does not verify that an operator supplied authoritative details or obtained approval. The release owner retains that evidence and controls publication. Use the intended deployment environment, because changing environment values on Vercel applies to new deployments. [Vercel environment configuration](https://vercel.com/docs/environment-variables)

The Eagle Security drafts link readers to account sign-in for the existing Profile → Privacy and data controls. Before raising the release gate, confirm who actually operates the service, the verified contact and jurisdiction details, which providers and processing regions are enabled, and any applicable policy approval. The exact publication bundle should describe those actual arrangements. [European Commission transparency obligations](https://commission.europa.eu/law/law-topic/data-protection/information-business-and-organisations/obligations_en)

Public-site browser coverage exercises the drafts and the effective state with a synthetic local bundle, the account sign-in link, and the unsigned DPA template.

## Community Rules at sign-in

The consumer web app displays the active Community Rules after account and authenticator checks and before opening workspace and messaging screens. Each account explicitly accepts each version. PostgreSQL records the version and time once per account. A newly effective version requires fresh acceptance. Users can sign out from the prompt.

The release operator publishes the approved plain-text rules through the private `sectalk_private.st_v8_community_rules` registry. Give each effective version a distinct `version` and `effective_at` and supply the approved `title` and ordered JSON array of rules. Keep the approval record with the release. Publish a higher effective version for corrections. The deployment review includes an acceptance test on the v6 backend before traffic is enabled. Formal Terms and Privacy have separate publication approval.

The following draft covers the product's reporting and enforcement workflow:

- Treat everyone with respect. Harassment, threats, stalking, repeated unwanted contact, and sharing sexual material without consent are prohibited.
- Do not impersonate people, spam users, run scams or use SecTalk to commit fraud.
- Respect privacy. Share personal information and private content only with permission. When reporting harm, include relevant details and evidence.
- Use the report controls when something goes wrong. You can follow the report's status and see actions that SecTalk can share with you.
- Authorized safety staff review reports under the service policy. They can warn, restrict or restore accounts and record their reasons.
