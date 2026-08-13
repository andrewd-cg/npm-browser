# BUN_TAG selects the bun base image tag — `latest` for the normal image,
# `latest-dev` for the -dev variant (dev image ships a shell/apk). Declared
# before the first FROM so it can be referenced in the base image stage.
ARG BUN_TAG=latest

FROM cgr.dev/chainguard/chainctl:latest AS chainctl

FROM cgr.dev/andrewd.dev/bun:${BUN_TAG}
COPY --from=chainctl /usr/bin/chainctl /usr/local/bin/chainctl
WORKDIR /app
COPY server.js index.html ./
EXPOSE 3000
CMD ["run", "server.js"]
