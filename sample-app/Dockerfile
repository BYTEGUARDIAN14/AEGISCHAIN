# syntax=docker/dockerfile:1
FROM golang:1.23.2-alpine@sha256:9dd2625a1ff2859b8d8b01d8f7822c0f528942fe56cfe7a1e7c38d3b8d72d679 AS builder

WORKDIR /src
COPY main.go go.mod ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /bin/sample-app ./main.go

FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3

USER 65532:65532
COPY --from=builder /bin/sample-app /bin/sample-app

EXPOSE 8080
ENTRYPOINT ["/bin/sample-app"]
