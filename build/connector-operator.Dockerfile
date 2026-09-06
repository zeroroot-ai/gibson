# Multi-stage build for the gibson connector-operator (ADR-0014).
FROM golang:1.26 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/connector-operator ./operators/connector/cmd

FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=build /out/connector-operator /connector-operator
USER 65532:65532
ENTRYPOINT ["/connector-operator"]
