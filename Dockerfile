# Control plane — the deterministic Big Loop (orchestrator on @opencode-ai/sdk).
# Alpine + Node + built dist + opencode config/agents/skills. Engines are
# separate `opencode serve` containers, driven over HTTP by the SDK client.
FROM node:20-alpine

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY dist ./dist
COPY opencode.json ./
COPY .opencode ./.opencode
COPY skills ./skills

ENV NODE_ENV=production
CMD ["node", "dist/scan-cli.js"]
