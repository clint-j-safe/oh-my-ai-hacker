# SAFE AI Hacker orchestrator.
# BUILD CONTEXT = REPO ROOT (not orchestrator/), because the skill test suite and
# skill_run both need skills/ present at ../skills relative to the orchestrator,
# and skill_run shells `python3 scripts/run.py`. Build with:
#   docker build -f orchestrator/Dockerfile -t sahw-orchestrator .
# Runs with network_mode: host to reach the operator host's Langfuse / ClickHouse /
# Neo4j on localhost and the in-scope target.
FROM node:22-alpine

# python3 is REQUIRED: skill_run executes the Python skills, and the suite spawns
# real ones. The permitted phase-1 skills are stdlib-only; a later phase enabling
# httpx-based skills must add py3-pip and those packages here.
RUN apk add --no-cache python3

WORKDIR /app/orchestrator

# Deps first so a source change does not bust the dep layer.
COPY orchestrator/package.json orchestrator/package-lock.json ./
RUN npm ci

COPY orchestrator/tsconfig.json ./
COPY orchestrator/src ./src
COPY orchestrator/test ./test
# skills/ sits at the repo root; place it at ../skills so process.cwd()/../skills
# resolves both in the test suite and at runtime (SAHW_SKILLS_ROOT default).
COPY skills /app/skills

# Fail the build if the code does not type-check or the suite does not pass —
# now including the skill tests that spawn real Python skills.
RUN npm test

RUN mkdir -p /workspace
ENV SAHW_WORKSPACE=/workspace SAHW_SKILLS_ROOT=/app/skills
ENTRYPOINT ["npx", "tsx", "src/cli.ts"]
