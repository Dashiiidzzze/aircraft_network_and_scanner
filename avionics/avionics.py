# avionics.py
# Модуль авионики: приём телеметрии от контроллеров (UDP) и передача данных в безопасный шлюз (HTTP)

import socket        # Для UDP-приёма
import json          # Для обработки сообщений
import requests      # Для HTTP-отправки в безопасный шлюз

# --- Конфигурация ---
UDP_PORT = 5004                              # Порт для приёма от контроллеров
GATEWAY_URL = "http://secure_gateway:8083/ingest"  # URL безопасного шлюза

# --- Получение и передача данных ---
def main():
    # Инициализация UDP-сокета
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", UDP_PORT))
    print(f"[Avionics] Ожидаем данные от контроллеров на порту {UDP_PORT}...")

    while True:
        data, addr = sock.recvfrom(4096)  # Получаем UDP-пакет
        try:
            controller_data = json.loads(data.decode("utf-8"))
            print(f"[Avionics] Получены данные от контроллера: {controller_data}")

            # Здесь могла бы быть логика проверки / фильтрации / агрегации

            # Отправка сводной информации в безопасный шлюз
            response = requests.post(GATEWAY_URL, json=controller_data)
            if response.status_code == 200:
                print("[Avionics] Данные успешно отправлены в шлюз.")
            else:
                print(f"[Avionics] Ошибка при отправке в шлюз: {response.status_code}")

        except json.JSONDecodeError:
            print("[Avionics] Ошибка разбора JSON.")
        except requests.exceptions.RequestException as e:
            print(f"[Avionics] Ошибка связи с шлюзом: {e}")

# Точка входа
if __name__ == "__main__":
    main()
