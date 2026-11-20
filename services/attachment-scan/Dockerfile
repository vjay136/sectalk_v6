FROM node:24-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends clamav python3 qpdf \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /worker
COPY worker.mjs inspect.py .
USER node
EXPOSE 8080
CMD ["node", "/worker/worker.mjs"]
