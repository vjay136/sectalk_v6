ARG AWS_CLI_VERSION=2.41.1
FROM public.ecr.aws/aws-cli/aws-cli:${AWS_CLI_VERSION} AS cli
FROM node:24-bookworm-slim
COPY --from=cli /usr/local/aws-cli /usr/local/aws-cli
WORKDIR /srv/tenant-dek
COPY adapter.mjs worker.mjs erasure-attestor.mjs erasure-worker.mjs cloudtrail-key-material.mjs cloudtrail-key-deletion.mjs verify-custody.mjs s3-recovery-copy-inventory.mjs recovery-copy-provenance.mjs recovery-coverage.mjs ./
USER node
EXPOSE 8080
CMD ["node", "/srv/tenant-dek/worker.mjs"]
