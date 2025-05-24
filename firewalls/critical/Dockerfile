FROM alpine:latest

# Устанавливаем iptables и bash
RUN apk add --no-cache iptables bash

COPY entrypoint.sh /entrypoint.sh
COPY critical.rules /rules.v4

# Даём права на выполнение скрипта
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
