# syntax=docker/dockerfile:1

FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS build
WORKDIR /src

# Restore separately from the source so a code change does not invalidate the package layer.
COPY global.json Directory.Build.props ./
COPY src/Oko/Oko.csproj src/Oko/
RUN dotnet restore src/Oko/Oko.csproj

COPY src/ src/
RUN dotnet publish src/Oko/Oko.csproj -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0-alpine AS runtime

# wget for the health check; it is already present in the alpine base but pin the intent here.
RUN addgroup -S oko && adduser -S -G oko oko && mkdir -p /data && chown oko:oko /data

WORKDIR /app
COPY --from=build /app ./

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
