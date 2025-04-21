FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o allsum main.go

FROM alpine
WORKDIR /app
COPY --from=builder /app/allsum .
ENTRYPOINT ["/app/allsum"]
