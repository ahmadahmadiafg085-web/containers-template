# syntax=docker/dockerfile:1

########## BUILDER ##########
FROM golang:1.24-alpine AS build

# Set working directory
WORKDIR /app

# ------------------- Go dependencies -------------------
COPY container_src/go.mod container_src/go.sum ./
RUN go mod download

# ------------------- Copy source -------------------
COPY container_src/*.go ./

# ------------------- Build static binary -------------------
RUN CGO_ENABLED=0 GOOS=linux go build -o server

# ------------------- Copy static HTML/Loader -------------------
COPY server_src/static ./static

# ------------------- Copy configuration files -------------------
COPY server_src/config ./config

########## FINAL IMAGE ##########
FROM scratch

# ------------------- Create directories -------------------
# در Cloudflare نیازی به cgroup یا runtime پیچیده نیست
WORKDIR /app
COPY --from=build /app/server /app/server
COPY --from=build /app/static /app/static
COPY --from=build /app/config /app/config
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# ------------------- Expose single port -------------------
# Cloudflare خودش مسیر routing را مدیریت می‌کند
EXPOSE 8080

# ------------------- Default command -------------------
CMD ["/app/server"]
