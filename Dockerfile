# 0xNotes Go Server Multi-stage Build

# BUILD
FROM golang:1.18-alpine as builder
RUN mkdir /build
COPY . /build
WORKDIR /build
RUN go build -ldflags="-s -w" -o server .

# COMPRESS
RUN apk add --no-cache upx
RUN upx --best --lzma server

# FINAL
FROM alpine:latest
COPY --from=builder /build/server .
ENV GIN_MODE release 
ENTRYPOINT ["./server"]
