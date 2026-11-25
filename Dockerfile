# syntax=docker/dockerfile:1.7
# vpn-egress: two images from one repo.
#   --target router  privileged half (host network, NET_ADMIN): exits, nftables, dnsmasq
#   --target panel   web UI, non-root (uid 10300), no capabilities needed

ARG PYTHON_IMAGE=python:3.13-slim

# amneziawg-tools, for the status of an AmneziaWG tunnel (not packaged in Debian).
FROM debian:trixie-slim AS awg
ARG AWG_TOOLS_REF=v3.1.20260812
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential ca-certificates git \
 && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch "$AWG_TOOLS_REF" https://github.com/amnezia-vpn/amneziawg-tools.git /src \
 && make -C /src/src -j"$(nproc)" wg \
 && install -m 0755 /src/src/wg /awg

# Each image gets its own venv, built at its final path (/venv): scripts'
# shebangs point at the venv's python.
FROM ${PYTHON_IMAGE} AS build-router
COPY --from=ghcr.io/astral-sh/uv:0.13.7 /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never UV_PROJECT_ENVIRONMENT=/venv
WORKDIR /src
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

FROM ${PYTHON_IMAGE} AS build-panel
COPY --from=ghcr.io/astral-sh/uv:0.13.7 /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never UV_PROJECT_ENVIRONMENT=/venv
WORKDIR /src
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project --extra panel
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable --extra panel

FROM ${PYTHON_IMAGE} AS router
ARG VERSION=dev
LABEL org.opencontainers.image.title="vpn-egress-router" \
      org.opencontainers.image.description="vpn-egress router: VPN exits, nftables routing and dnsmasq" \
      org.opencontainers.image.source="https://github.com/agmike/vpn-egress" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 nftables wireguard-tools dnsmasq-base \
 && rm -rf /var/lib/apt/lists/*
COPY --from=awg /awg /usr/local/bin/awg
COPY --from=build-router /venv /venv
ENV PATH=/venv/bin:$PATH PYTHONUNBUFFERED=1 VPN_EGRESS_VERSION=${VERSION}
CMD ["vpn-egress-router"]

FROM ${PYTHON_IMAGE} AS panel
ARG VERSION=dev
LABEL org.opencontainers.image.title="vpn-egress-panel" \
      org.opencontainers.image.description="vpn-egress web panel" \
      org.opencontainers.image.source="https://github.com/agmike/vpn-egress" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"
RUN useradd --uid 10300 --system --no-create-home panel
COPY --from=build-panel /venv /venv
ENV PATH=/venv/bin:$PATH PYTHONUNBUFFERED=1 BUILD_SHA=${VERSION}
USER 10300
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3)"]
CMD ["uvicorn", "vpn_egress.panel.app:app", "--factory", "--host", "0.0.0.0", "--port", "8080", \
     "--proxy-headers", "--forwarded-allow-ips", "*"]
