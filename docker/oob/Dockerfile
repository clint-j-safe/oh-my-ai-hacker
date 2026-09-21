# OOB / OAST listener (reverse-shell + out-of-band callback catcher)
# Minimal Alpine image — only node + 3 built JS files, no external deps.
FROM node:20-alpine

WORKDIR /app
COPY dist/oob-server.js dist/oob.js dist/dns.js /app/dist/

ENV OOB_ANSWER_IP=127.0.0.1 \
    OOB_DNS_PORT=53 \
    OOB_HTTP_PORT=80 \
    OOB_SHELL_PORT=4444

EXPOSE 53/udp 53/tcp 80/tcp 4444/tcp

CMD ["node", "/app/dist/oob-server.js"]
