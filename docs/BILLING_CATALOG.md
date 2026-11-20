# Billing catalog

Billing → Compare plans reads the active Supabase catalog. Free and Enterprise have no self-service prices. Existing Basic subscribers keep their terms. Pro and Team use the existing professional and business entitlement IDs.

Billing operators publish an immutable plan revision through `st_v6_publish_plan` using the server-side billing role. Each revision supplies the full set of offers for its activation timestamp. An offer includes the interval, ISO currency, amount in minor units and an immutable Stripe Price ID. Use one fixed, licensed recurring Stripe price per offer. Configure amounts and activate a revision only after its Stripe prices are ready. Checkout compares the selected offer to Stripe before creating a session. [Stripe price documentation](https://docs.stripe.com/products-prices/manage-prices)

Future revisions become visible at the activation timestamp. Existing subscriptions keep the revision recorded for the Stripe price that renews. Preserve historic prices and legacy environment mappings for webhook lookup. A change to a customer's actual Stripe price deliberately changes the recorded terms.

The local acceptance test covers catalog reads, currency and interval controls, stale selection, subscription isolation, signed webhook handling and grandfathered terms. Hosted customer checkout remains a separate Stripe sandbox acceptance test.
