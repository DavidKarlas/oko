# syntax=docker/dockerfile:1

# Pinned to the build host's own architecture, then cross-compiled to the target with `dotnet -a`.
# Without --platform=$BUILDPLATFORM, buildx would emulate the foreign architecture through QEMU to run
# the SDK, which takes minutes per platform instead of seconds.
FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS build

ARG TARGETARCH
WORKDIR /src

# Restore separately from the source so a code change does not invalidate the package layer.
COPY global.json Directory.Build.props ./
COPY src/Oko/Oko.csproj src/Oko/
# Docker's TARGETARCH says amd64/arm64; .NET's -a wants x64/arm64.
RUN DOTNET_ARCH=$(echo "$TARGETARCH" | sed 's/^amd64$/x64/') \
    && dotnet restore src/Oko/Oko.csproj -a "$DOTNET_ARCH"

COPY src/ src/
RUN DOTNET_ARCH=$(echo "$TARGETARCH" | sed 's/^amd64$/x64/') \
    && dotnet publish src/Oko/Oko.csproj -c Release -a "$DOTNET_ARCH" -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0-alpine AS runtime

RUN addgroup -S oko && adduser -S -G oko oko && mkdir -p /data && chown oko:oko /data

WORKDIR /app
COPY --from=build /app ./

# Shipped so an operator can pull the VM-side tap out of the image rather than cloning the repo.
# --entrypoint is required: without it the arguments are passed to Oko and the collector just starts.
#   docker run --rm --entrypoint cat davidkarlas/oko /usr/local/share/oko/oko-tap > oko-tap
#   chmod +x oko-tap
COPY tools/oko-tap/oko-tap /usr/local/share/oko/oko-tap
RUN chmod 0755 /usr/local/share/oko/oko-tap

USER oko
VOLUME /data

# 37008/udp takes TZSP from MikroTik and similar sensors; 37009/tcp takes pcap streams from Linux hosts
# running oko-tap; 8080/tcp serves the captures.
EXPOSE 8080/tcp
EXPOSE 37008/udp
EXPOSE 37009/tcp

ENV ASPNETCORE_URLS=http://+:8080 \
    OKO_DATA_DIR=/data \
    DOTNET_gcServer=1

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["./Oko"]

# Populated by scripts/publish.sh. Kept last so editing them does not invalidate any build layer.
ARG OKO_VERSION=0.0.0
ARG OKO_REVISION=unknown
LABEL org.opencontainers.image.title="Oko" \
      org.opencontainers.image.description="Always-on TZSP and pcap capture collector; serves pcapng over HTTP for Wireshark." \
      org.opencontainers.image.version="$OKO_VERSION" \
      org.opencontainers.image.revision="$OKO_REVISION" \
      org.opencontainers.image.source="https://github.com/DavidKarlas/oko" \
      org.opencontainers.image.url="https://github.com/DavidKarlas/oko" \
      org.opencontainers.image.documentation="https://github.com/DavidKarlas/oko#readme" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.authors="David Karlaš"
