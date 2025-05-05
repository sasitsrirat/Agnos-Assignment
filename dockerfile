# Dockerfile
FROM golang:1.24 AS builder

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY . .

RUN go build -o server .

# Runtime image
FROM gcr.io/distroless/base-debian11

WORKDIR /root/

COPY --from=builder /app/server .
COPY --from=builder /app/.env .

CMD ["./server"]
