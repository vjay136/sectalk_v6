# V6 implementation decisions

- Start from the published v5.0.0 commit. V6 is a separate candidate. The existing hosted Supabase Auth configuration and the v5 domain continue serving v5.
- Keep the working npm workspace and Supabase contracts during incremental implementation. The requested pnpm and Turborepo layout, separate admin and worker deployments, and infrastructure adapters still need migration and contract testing.
- Existing direct conversations keep the current contact and message permissions. Saved messages reference the authorized source row. They inherit revocation and personal hide through row-level security.
- The supplied brief excludes public discovery outside a tenant for its target version. V5 currently has optional adult discovery. This branch needs a product decision and compatibility work before switching the target release to tenant-only discovery.
- Production promotion requires the complete registry gate and release verification. Local validation uses a separate Supabase instance and test mail inbox.
