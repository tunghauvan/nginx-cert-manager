FROM python:3.13-alpine

LABEL maintainer="tunghau.jp@interspace.vn"

RUN apk add --no-cache certbot certbot-dns-route53