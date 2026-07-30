FROM ghcr.io/home-assistant/base:3.24

ARG BUILD_VERSION=0.2.0
ARG BUILD_ARCH

LABEL \
  io.hass.version="${BUILD_VERSION}" \
  io.hass.type="app" \
  io.hass.arch="${BUILD_ARCH}"

RUN apk add --no-cache python3 py3-aiohttp

WORKDIR /app
COPY run.sh server.py /app/
RUN chmod 0755 /app/run.sh

EXPOSE 8765
ENTRYPOINT [ "/app/run.sh" ]
