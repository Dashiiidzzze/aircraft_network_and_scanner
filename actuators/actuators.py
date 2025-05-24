# Этот скрипт имитирует работу исполнительных механизмов самолета.
# Он получает команды от контроллеров по UDP и "выполняет" их, выводя в лог.

import socket
import json

UDP_PORT = 5002  # Порт для приёма управляющих команд

# Создаем UDP-сокет и привязываем его к порту
udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_sock.bind(("", UDP_PORT))  # Слушаем на всех интерфейсах

print(f"[Actuators] Ожидание команд на порту {UDP_PORT}...")

while True:
    # Получаем сообщение
    data, addr = udp_sock.recvfrom(4096)

    try:
        # Декодируем JSON-данные
        command = json.loads(data.decode("utf-8"))
        
        # Выводим в консоль имитацию выполнения команды
        print(f"[Actuators] Получена команда от {addr}:")
        for system, value in command.items():
            print(f"    → {system}: {value}")
        print("    ⚙ Выполнение команды завершено.\n")

    except json.JSONDecodeError:
        print("[Actuators] Ошибка: получены некорректные данные.")
