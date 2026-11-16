FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -p 2 -trimpath -ldflags="-s -w" -o /chaincert .

FROM alpine:3.23@sha256:469c9ea410b9215eaee7976ba6c0639039b444be8e5d638f7abbada189971eb2
RUN apk add --no-cache ca-certificates
COPY --from=build /chaincert /usr/local/bin/chaincert
ENV GOMEMLIMIT=128MiB
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/chaincert"]
