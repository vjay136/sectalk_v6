# Server observability

Configure `SECTALK_OTLP_ENDPOINT` with an HTTPS OpenTelemetry HTTP receiver base URL. If the receiver needs a bearer credential, set `SECTALK_OTLP_BEARER_TOKEN` as a private server variable. SecTalk sends OTLP JSON to the receiver's `v1/traces`, `v1/metrics` and `v1/logs` paths. Loopback HTTP is available for local verification. [OTLP protocol](https://opentelemetry.io/docs/specs/otlp/)

The instrumented file, call, meeting, billing and health operations record request traces and duration histograms. The histogram count gives the request rate and its status-class attribute supports error-rate alerts. Existing staff dashboards retain their database-backed view of latency and concurrency. Requests classified as server errors emit a correlated log. The framework error hook also reports unexpected server errors under a stable category.

Search for the `sectalk.error.fingerprint` attribute to group failures and use the trace ID on a log record to find the corresponding span. Telemetry only includes a fixed operation name, status, timing and server-generated identifiers. Raw request paths, query strings, bodies, headers, client addresses, error messages and user identities stay out of these signals.

Exports use bounded batches after responses. An unavailable or slow collector can drop telemetry while SecTalk continues serving requests.
