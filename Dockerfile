# Project Astro V2 — LLM-Driven Penetration Testing MCP Server
# Base: Kali Linux Rolling | Multi-stage build

# --------------- Stage 1: Python dependency builder ---------------
FROM kalilinux/kali-rolling AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

RUN python3 -m venv /opt/astro-venv
ENV PATH="/opt/astro-venv/bin:$PATH"

COPY pyproject.toml README.md ./
COPY src/ src/
RUN pip install --no-cache-dir ".[reporting]"


# --------------- Stage 2: Runtime ---------------
FROM kalilinux/kali-rolling AS runtime

LABEL maintainer="Project Astro <mohammedrizvan96@gmail.com>"
LABEL description="Project Astro V2 — LLM-driven penetration testing MCP server"

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        python3-venv \
        nmap \
        gobuster \
        dirb \
        nikto \
        sqlmap \
        metasploit-framework \
        hydra \
        john \
        wpscan \
        enum4linux \
        subfinder \
        amass \
        ffuf \
        whatweb \
        dnsrecon \
        theharvester \
        exploitdb \
        crackmapexec \
        hashcat \
        responder \
        smbclient \
        evil-winrm \
        curl \
        ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --from=builder /opt/astro-venv /opt/astro-venv
ENV PATH="/opt/astro-venv/bin:$PATH"

RUN useradd --create-home --shell /bin/bash astro \
    && mkdir -p /home/astro/.astro \
    && chown -R astro:astro /home/astro

WORKDIR /app
COPY --chown=astro:astro . .

# The standalone image is loopback-only by default. Deployments that override
# ASTRO_HOST to a non-loopback address must also configure API_KEY or OIDC.
ENV ASTRO_HOST=127.0.0.1 \
    ASTRO_PORT=8080 \
    ASTRO_TRANSPORT=streamable-http \
    ASTRO_DB_PATH=/home/astro/.astro/engagements.db \
    ASTRO_DEBUG=false

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:8080/health || exit 1

USER astro

CMD ["astro", "serve", "--transport", "streamable-http", "--port", "8080", "--host", "127.0.0.1"]
