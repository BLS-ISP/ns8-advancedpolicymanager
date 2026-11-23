# Multi-stage application image for NS8-AdvancedPolicyManager
FROM docker.io/library/node:22-alpine AS web-builder
WORKDIR /deps
COPY web/package*.json ./
RUN npm install
WORKDIR /src/web
COPY web/ ./
RUN rm -rf node_modules dist && cp -a /deps/node_modules ./node_modules && npm run build

FROM docker.io/library/rust:1-bookworm AS agent-builder
WORKDIR /src/agent
COPY agent/Cargo.toml agent/Cargo.lock* ./
COPY agent/src ./src
RUN cargo build --release

FROM docker.io/library/python:3.12-slim-bookworm AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APM_PORT=8080 \
    APM_DATA_DIR=/data \
    APM_STATIC_DIR=/app/web_dist \
    APM_AGENT_ARTIFACTS_DIR=/app/agent_artifacts

WORKDIR /app

RUN mkdir -p /data \
             /app/web_dist \
             /app/agent_artifacts/binaries/linux/x86_64 \
             /app/agent_artifacts/installers && \
    chmod 0777 /data

COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/app ./app
COPY --from=web-builder /src/web/dist /app/web_dist
COPY --from=agent-builder /src/agent/target/release/ns8-policy-agent /app/agent_artifacts/binaries/linux/x86_64/ns8-policy-agent
COPY agent/installers/ /app/agent_artifacts/installers/

RUN sed -i 's/\r$//' /app/agent_artifacts/installers/*.sh && \
    chmod +x /app/agent_artifacts/binaries/linux/x86_64/ns8-policy-agent \
             /app/agent_artifacts/installers/*.sh

EXPOSE 8080
VOLUME ["/data"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
