# ==============================================================================
# Stage 1: Build Vue 3 Policy Admin Web Console
# ==============================================================================
FROM docker.io/library/node:22-alpine AS web-builder

WORKDIR /web
COPY web/package*.json ./
RUN npm ci || npm install
COPY web/ ./
RUN npm run build

# ==============================================================================
# Stage 2: Prepare Cross-Platform Rust Agent Binaries (CI prebuilt or compiled)
# ==============================================================================
FROM docker.io/library/rust:1-bookworm AS agent-builder

WORKDIR /src/agent
COPY agent/Cargo.toml agent/Cargo.lock* ./
COPY agent/src ./src
COPY prebuilt-agents/ /prebuilt-agents/

RUN mkdir -p /out/binaries/linux/x86_64 \
             /out/binaries/windows/x86_64 \
             /out/binaries/macos/x86_64 \
             /out/binaries/macos/aarch64 && \
    if [ -f /prebuilt-agents/linux/x86_64/ns8-policy-agent ]; then \
        cp /prebuilt-agents/linux/x86_64/ns8-policy-agent /out/binaries/linux/x86_64/ns8-policy-agent; \
    else \
        cargo build --release && \
        cp /src/agent/target/release/ns8-policy-agent /out/binaries/linux/x86_64/ns8-policy-agent; \
    fi && \
    chmod 0755 /out/binaries/linux/x86_64/ns8-policy-agent && \
    if [ -f /prebuilt-agents/windows/x86_64/ns8-policy-agent.exe ]; then \
        cp /prebuilt-agents/windows/x86_64/ns8-policy-agent.exe /out/binaries/windows/x86_64/ns8-policy-agent.exe; \
    fi && \
    if [ -f /prebuilt-agents/macos/x86_64/ns8-policy-agent ]; then \
        cp /prebuilt-agents/macos/x86_64/ns8-policy-agent /out/binaries/macos/x86_64/ns8-policy-agent && \
        chmod 0755 /out/binaries/macos/x86_64/ns8-policy-agent; \
    fi && \
    if [ -f /prebuilt-agents/macos/aarch64/ns8-policy-agent ]; then \
        cp /prebuilt-agents/macos/aarch64/ns8-policy-agent /out/binaries/macos/aarch64/ns8-policy-agent && \
        chmod 0755 /out/binaries/macos/aarch64/ns8-policy-agent; \
    fi

# ==============================================================================
# Stage 3: FastAPI Policy Engine Runtime Image
# ==============================================================================
FROM docker.io/library/python:3.12-slim-bookworm AS runtime

LABEL org.opencontainers.image.source="https://github.com/BLS-ISP/ns8-advancedpolicymanager" \
      org.opencontainers.image.description="FastAPI Policy Engine, Admin Web GUI & Cross-Platform Client Binaries for NS8-AdvancedPolicyManager" \
      org.opencontainers.image.vendor="BLS-ISP" \
      org.opencontainers.image.licenses="GPL-3.0-or-later"

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
             /app/agent_artifacts/binaries/windows/x86_64 \
             /app/agent_artifacts/binaries/macos/x86_64 \
             /app/agent_artifacts/binaries/macos/aarch64 \
             /app/agent_artifacts/installers && \
    chmod 0777 /data

COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/app ./app
COPY --from=web-builder /web/dist /app/web_dist
COPY --from=agent-builder /out/binaries/ /app/agent_artifacts/binaries/
COPY agent/installers/ /app/agent_artifacts/installers/

RUN sed -i 's/\r$//' /app/agent_artifacts/installers/*.sh && \
    chmod +x /app/agent_artifacts/binaries/linux/x86_64/ns8-policy-agent \
             /app/agent_artifacts/installers/*.sh

EXPOSE 8080
VOLUME ["/data"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
