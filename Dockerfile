FROM golang:1.25-alpine AS builder
WORKDIR /src

RUN apk add --no-cache ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /out/license-portal-backend .

FROM alpine:3.20
WORKDIR /app

RUN apk add --no-cache ca-certificates curl bind-tools iputils && \
    printf '#!/bin/sh\nexec ls -la "$@"\n' > /usr/local/bin/ll && \
    chmod +x /usr/local/bin/ll

COPY --from=builder /out/license-portal-backend /app/license-portal-backend

EXPOSE 8080
ENTRYPOINT ["/app/license-portal-backend"]
