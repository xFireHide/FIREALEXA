# Build with only this file and the verified JADX JAR in the build context.
# Network is needed for tool staging, never for analysis runs.
FROM node:24-bookworm-slim@sha256:be8204d4bd327363357f532187b752ff62759c31bedf98e9e18fc08c9cbd605c
RUN apt-get update && apt-get install -y --no-install-recommends openjdk-17-jdk-headless procps ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/rea
RUN npm install --ignore-scripts --omit=dev --no-audit --no-fund rea-agents@4.1.0 \
    && npm cache clean --force
COPY jadx-headless-mcp-0.7.1-all.jar /opt/rea/
RUN echo '6e5eacf500b64292bfb73c49797c1958f6ee44646e43e868039ae7feb573ff75  jadx-headless-mcp-0.7.1-all.jar' | sha256sum -c - \
    && printf '#!/bin/sh\nexec node /opt/rea/node_modules/rea-agents/scripts/rea.mjs "$@"\n' > /opt/rea/rea \
    && chmod 755 /opt/rea/rea
ENV HOME=/tmp TMPDIR=/tmp REA_JADX_MCP_JAR=/opt/rea/jadx-headless-mcp-0.7.1-all.jar
USER 65534:65534
ENTRYPOINT ["/opt/rea/rea"]
