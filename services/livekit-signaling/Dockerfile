FROM node:24-alpine@sha256:44fce696f38ba8c987c4db89954051000bbd05ffd8d8659ba15ed4a8602e937f
WORKDIR /srv
COPY server.mjs .
USER node
ENV BIND_HOST=0.0.0.0
EXPOSE 8080
CMD ["node","server.mjs"]
