FROM alpine:latest

COPY teeproxy.go /usr/local/src/

RUN apk add go musl-dev \
    && cd /usr/local/src/ \
    && CGO_ENABLED=0 go build teeproxy.go \
    && mv teeproxy /usr/local/bin/ \
    && apk del go musl-dev

ENTRYPOINT ["/usr/local/bin/teeproxy"]

EXPOSE 8888 9000 9001
