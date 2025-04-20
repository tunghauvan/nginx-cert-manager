FROM python:3.13-alpine

WORKDIR /app

LABEL maintainer="tunghau.jp@interspace.vn"

RUN apk add --no-cache certbot certbot-dns-route53

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY . /app

# Run the entrypoint script with the 'serve' command
CMD ["python", "entrypoint.py", "serve"]