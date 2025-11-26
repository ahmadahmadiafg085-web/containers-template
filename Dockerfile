# syntax=docker/dockerfile:1

########## BUILDER ##########
FROM golang:1.24-alpine AS build

WORKDIR /app

# Dependencies
COPY container_src/go.mod container_src/go.sum ./
RUN go mod download

# App source
COPY container_src/*.go ./

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux go build -o server

# Static assets + configs
COPY server_src/static ./static
COPY server_src/config ./config

########## FINAL ##########
FROM scratch

# Create working dirs
WORKDIR /app
RUN mkdir -p /etc/ssl/certs

# SSL
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Binary
COPY --from=build /app/server /server

# Static & config
COPY --from=build /app/static /app/static
COPY --from=build /app/config /app/config

# Flexible ports
EXPOSE 8080-8090

CMD ["/server"]
