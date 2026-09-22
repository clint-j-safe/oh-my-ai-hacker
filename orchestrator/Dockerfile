# SAFE AI Hacker orchestrator.
# Runs with network_mode: host so it can reach the operator host's existing
# Langfuse / ClickHouse / Neo4j on localhost, and the in-scope target.
FROM node:22-alpine

WORKDIR /app

# Install deps first so a source change does not invalidate the dep layer.
COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src
COPY test ./test

# Fail the build if the code does not type-check or the suite does not pass.
# A container that ships a broken orchestrator is worse than a failed build.
RUN npm test

# Artifacts and evidence land here; mount a volume over it to keep them.
RUN mkdir -p /workspace
ENV SAHW_WORKSPACE=/workspace

ENTRYPOINT ["npx", "tsx", "src/cli.ts"]
