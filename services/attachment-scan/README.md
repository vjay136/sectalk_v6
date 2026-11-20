# Attachment scan worker

This private Node worker streams up to 4 MiB of staged attachment bytes into ClamAV. It runs one scan at a time and admits at most eight requests. Each response includes the SHA-256 computed from the bytes ClamAV received. The application compares it with the digest of the immutable Storage object before recording a verdict.

Build with `docker build -t sectalk-attachment-scan services/attachment-scan`. Mount a current, administrator-maintained official ClamAV signature directory read-only at `/definitions`. Keep the engine and definitions updated separately from the worker. The local regression uses a benign synthetic signature fixture, which is suitable only for testing.

For the loopback regression, a test-only `.ndb` file can define `SecTalk.QA.Benign.Marker:0:*:<hex bytes>`, using the UTF-8 hexadecimal encoding of `SecTalk benign isolated scanner marker v6`. Run `node tests/attachment-scan-worker.e2e.mjs` with the local origin and secret.

Use a read-only, non-root container with dropped capabilities, no-new-privileges, CPU, memory and PID limits, and a bounded writable `/tmp` mount. Choose memory based on official definition size. Place the service behind private HTTPS ingress and block worker egress at the deployment network. For loopback-only QA use `http://127.0.0.1:3487`. Set `SECTALK_MALWARE_SCANNER_URL` on the app and configure the same independent 32-byte-minimum `SECTALK_MALWARE_SCANNER_SECRET` in both processes. Keep Storage credentials outside the scanner.

The configured gate quarantines unavailable and unverified scans. The sender can retry the staged object from Files → Pending security scans, even after reopening the browser. A designated MFA reviewer with a row in `sectalk_private.st_v6_file_scan_reviewers` can record a reason and release a matching clean re-scan. Reviewers cannot release their own attachment, and recorded malware hashes cannot be released. Quarantine remains private, with unpublished objects eligible for the attachment purge worker after 24 hours.
