# syntax=docker/dockerfile:1

########## BUILDER ##########
FROM golang:1.24-alpine AS build

WORKDIR /app

# Download dependencies first (cache friendly)
COPY container_src/go.mod ./
RUN go mod download

# Copy source code
COPY container_src/*.go ./

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux go build -o server

########## FINAL IMAGE ##########
FROM scratch

# Copy SSL certificates
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy binary
COPY --from=build /app/server /server

EXPOSE 8080

CMD ["/server"]
