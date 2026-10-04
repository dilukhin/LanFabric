FROM golang:1.24.4-bookworm AS go-build
ARG AWG_GO_SHA=1cc94272ca8e9e223a5fe76382f5880f09d3c12d
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/amnezia-vpn/amneziawg-go.git /src && cd /src && git checkout --detach "$AWG_GO_SHA" && test "$(git rev-parse HEAD)" = "$AWG_GO_SHA"
WORKDIR /src
RUN go mod download && go mod verify && CGO_ENABLED=0 go build -trimpath -o /amneziawg-go .

FROM debian:bookworm-slim AS tools-build
ARG AWG_TOOLS_SHA=5e882890fbca2316f8ca40e992789d24f67f0118
RUN apt-get update && apt-get install -y --no-install-recommends git make gcc libc6-dev ca-certificates && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/amnezia-vpn/amneziawg-tools.git /src && cd /src && git checkout --detach "$AWG_TOOLS_SHA" && test "$(git rev-parse HEAD)" = "$AWG_TOOLS_SHA" && make -C src

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 iptables iputils-ping python3 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=go-build /amneziawg-go /usr/local/bin/amneziawg-go
COPY --from=tools-build /src/src/wg /usr/local/bin/awg
COPY start.sh /usr/local/bin/probe-start
RUN chmod 0755 /usr/local/bin/probe-start
ENTRYPOINT ["/usr/local/bin/probe-start"]
