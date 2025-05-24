#!/bin/bash

# Для наглядности выводим статус iptables до применения
echo "[INFO] Текущие правила iptables:"
iptables -L -v -n

# Включаем IP переадресацию
echo 1 > /proc/sys/net/ipv4/ip_forward

# DNAT: все запросы к firewall:8083 → secure_gateway:8083
iptables -t nat -A PREROUTING -p tcp -d 10.10.1.8 --dport 8083 -j DNAT --to-destination 10.10.4.9:8083

# SNAT: подменяем исходный IP на IP фаервола (если нужно)
iptables -t nat -A POSTROUTING -p tcp -d 10.10.4.9 --dport 8083 -j MASQUERADE


# Применяем конфигурацию из файла
echo "[INFO] Применяем правила из /rules.v4"
iptables-restore < /rules.v4

# Показываем текущие правила после применения
echo "[INFO] Применённые правила:"
iptables -L -v -n
iptables -t filter -L FORWARD -v --line-numbers

# Ждём бесконечно, чтобы контейнер оставался активным
tail -f /dev/null
