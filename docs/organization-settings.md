# Organization settings deployment

Workspace owners manage branding, default room retirement retention, DNS-verified domains, and a preferred data region under **Workspaces → Organization settings**. Writes require a fresh sign-in and appear in the workspace audit feed where applicable.

## DNS verification

- Set `SECTALK_ORG_DNS_SERVER` to the IPv4 address of a trusted recursive resolver. Append a port only when it differs from 53. Configure the resolver for public DNS and restrict the application runtime to that resolver for outbound DNS.
- Set `SECTALK_ORG_DOMAIN_SERVICE_KEY` through server-only secret management. It must authorize the service-role domain finalization RPC and must never use a `NEXT_PUBLIC_` prefix.
- An owner creates a challenge, publishes the displayed TXT record, and requests an explicit check within 48 hours. SecTalk records verification only when the configured resolver returns the exact value. A timeout or missing record leaves it unverified. If DNS configuration is absent, the check reports that the service is unavailable.
- A verified association records control at the time of verification. Owners can remove it in settings. Verified associations do not enroll users or change invitation rules.

## Region and retention

- Set `SECTALK_ORG_INFRA_REGION` and `SECTALK_ORG_INFRA_REGION_REFERENCE` only after confirming the applicable deployment region against infrastructure records. Provide a short, display-safe change or inventory reference. SecTalk shows this operator declaration as unavailable if either field is absent or invalid. It does not discover location from hosting request metadata or independently measure storage residency.
- A workspace's saved preferred location is advisory. Relocation and cross-service residency remain separate operational work.
- The room retirement worker uses the effective workspace retention default when deciding whether an archived room is eligible for permanent deletion. Existing legal holds remain enforceable. Other retention surfaces have separate policies.
