# Stage 1: Build Node/TS
FROM node:22-alpine as builder
WORKDIR /app
COPY package*.json tsconfig.json ./
COPY src ./src
RUN npm install && npm run build

# Stage 2: Build Go
FROM golang:1.25-alpine as go-builder
WORKDIR /go/src/app
COPY container_src ./
RUN go build -o /app/go-server main.go

# Stage 3: Final image
FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=go-builder /app/go-server ./go-server
COPY server_src ./server_src
EXPOSE 8080
CMD ["./go-server"]
