# Delegated workspace billing

Workspace owners can open **Billing → Manage workspace billing access**. Recent billing proof is required to read or change grants. The proof uses the same native assurance as subscription checkout. The owner selects an existing, active member and explicitly grants billing access. Grants do not confer a workspace administrator role. Suspension, removal, or revocation ends access.

A delegated billing administrator can open **Billing → Workspace billing** to view the tenant's active paid or trial plan, occupied seats and limits, and monthly usage. The dashboard checks the specific workspace grant every time. The owner can manage grants without entering the delegated dashboard, and an ordinary workspace administrator lacks billing access until assigned.

SecTalk returns recent invoice summaries and subscription payment status for the exact Stripe customer and subscription linked to the owner. The owner's subscription can cover several workspaces, and the grant screen explains that its invoice summaries come from that subscription. The app checks both Stripe identifiers on the request and response. Card details, billing addresses, contact details and hosted invoice URLs stay outside the delegated dashboard.

Stripe currently creates account-wide customer portal sessions. Those sessions remain in the account owner's existing self-service flow. A workspace billing grant does not create a portal session, change a subscription or payment method, issue a refund, or expose another subscription's invoices. Hosted Stripe data and configuration require deployment verification.
