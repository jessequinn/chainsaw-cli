FROM golang:1.22-alpine AS builder
RUN apk add --no-cache git
COPY . .
RUN go build -o app .

FROM alpine:3.19
COPY --from=builder /app /app
EXPOSE 8080
CMD ["/app"]
