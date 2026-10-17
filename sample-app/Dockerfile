# syntax=docker/dockerfile:1
FROM golang:1.23.2-alpine@sha256:ad7077382d56d50ff513d6a992e59e519213190892224d529141013a7c64aadc AS builder

WORKDIR /src
COPY main.go go.mod ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /bin/sample-app ./main.go

FROM gcr.io/distroless/static:nonroot@sha256:6ec5aa99dc33c56d5b79dc1a68b6a14704a4fa8b9152b84d08891ad85ec2d1da

USER 65532:65532
COPY --from=builder /bin/sample-app /bin/sample-app

EXPOSE 8080
ENTRYPOINT ["/bin/sample-app"]
