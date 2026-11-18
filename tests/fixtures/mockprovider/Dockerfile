# The mock model provider and its TLS front, for the exit tests of the AAIF
# epics. The build context is the root of the gibson repo. The workflow builds
# this image in the run and loads it into kind, so it never leaves the run.
FROM ghcr.io/zeroroot-ai/mirror/golang:1.27.3-alpine@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd AS builder
ARG GOTOOLCHAIN=local
ENV GOTOOLCHAIN=${GOTOOLCHAIN}
WORKDIR /src
COPY tests/fixtures/mockprovider/main.go ./mockprovider/main.go
COPY tests/fixtures/mockprovider/tlsfront/main.go ./tlsfront/main.go
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/mockprovider ./mockprovider/main.go \
 && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/tlsfront ./tlsfront/main.go

FROM ghcr.io/zeroroot-ai/mirror/distroless-static:nonroot@sha256:d62067879de890a1def9da0e7766b7d20810a5e5555cef8506b752437d7a3e88
COPY --from=builder /out/mockprovider /mockprovider
COPY --from=builder /out/tlsfront /tlsfront
EXPOSE 8443 18080
ENTRYPOINT ["/mockprovider"]
