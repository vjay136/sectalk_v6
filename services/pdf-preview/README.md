# PDF preview worker

The application sends an already-authorized attachment to this optional service and re-encodes its first-page raster as PNG. The application applies authorization again before releasing the image. The worker accepts up to 1 MiB per PDF and one active conversion at a time.

Build with `docker build -t sectalk-pdf-preview services/pdf-preview`. Set `SECTALK_PDF_WORKER_SECRET` to an independently generated secret of at least 32 bytes in both environments. One local deployment is:

```sh
docker run --rm --name sectalk-pdf-preview --read-only --cap-drop=ALL \
  --security-opt no-new-privileges=true --pids-limit=32 --memory=384m --cpus=0.75 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=8m -p 127.0.0.1:3486:8080 \
  --env SECTALK_PDF_WORKER_SECRET sectalk-pdf-preview
```

Set the application’s `SECTALK_PDF_PREVIEW_WORKER_URL` to `http://127.0.0.1:3486` for this topology. For separate hosts, place the worker behind private authenticated HTTPS ingress and use its HTTPS origin. Keep database and storage credentials outside the worker and use an isolated, unprivileged Linux container with the limits above.

Both Poppler subprocesses receive the document over a pipe and run under syscall and resource restrictions. Startup fails if the launcher cannot block IPv4, IPv6, and Unix socket creation. Encrypted, malformed, interactive, oversized, and excessively complex documents may be rejected. The worker emits only first-page raster output.
