FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PATH="/opt/cybergrok-venv/bin:/usr/local/bin:/workspace/tools/bin:${PATH}"
WORKDIR /workspace

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates python3 python3-pip python3-venv python3-dev \
    nodejs npm ripgrep nmap acl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md /workspace/
COPY python /workspace/python
COPY mcp /workspace/mcp
COPY tools /workspace/tools
COPY scripts /workspace/scripts
COPY skills /workspace/skills
COPY knowledge /workspace/knowledge
COPY templates /workspace/templates
COPY AGENTS.md plugin.json scope.yaml /workspace/
COPY setup.sh entrypoint.sh /workspace/

RUN python3 -m venv /opt/cybergrok-venv \
    && /opt/cybergrok-venv/bin/pip install --no-cache-dir -e /workspace \
    && cd /workspace/mcp && npm install && npm run build \
    && mkdir -p /workspace/reports /workspace/recon /workspace/targets /workspace/output /workspace/logs \
    && chmod +x /workspace/entrypoint.sh /workspace/scripts/cybergrok-mcp.sh \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin cybergrok \
    && chown -R cybergrok:cybergrok /workspace /opt/cybergrok-venv

USER cybergrok

ENTRYPOINT ["/workspace/entrypoint.sh"]
