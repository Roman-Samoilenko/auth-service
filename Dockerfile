FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /auth-service ./cmd/main.go

FROM alpine:3.19
RUN apk --no-cache add ca-certificates tzdata bash netcat-openbsd

COPY --from=builder /auth-service /auth-service
EXPOSE 8081

CMD ["/auth-service"]