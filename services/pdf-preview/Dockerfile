FROM node:24-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends libseccomp-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY raster-sandbox.c .
RUN cc -O2 -Wall -Wextra -Werror raster-sandbox.c -lseccomp -o raster-sandbox

FROM node:24-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends poppler-utils libseccomp2 fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /worker
COPY --from=build /build/raster-sandbox /worker/raster-sandbox
COPY worker.mjs .
USER node
EXPOSE 8080
CMD ["node", "/worker/worker.mjs"]
