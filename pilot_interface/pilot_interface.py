# pilot_interface.py
# Имитация интерфейса пилота: приём данных от сенсоров (UDP) и передача команд контроллерам (HTTP)

import socket       # Для UDP-приёма
import threading    # Чтобы одновременно слушать UDP и принимать команды пилота
import json         # Для обработки структурированных данных
import requests     # Для отправки HTTP-запросов
import time         # Для пауз между автоматическими командами
import random       # Для генерации случайных значений рулей и тяги

# Конфигурация
UDP_PORT = 5003                         # Порт для приёма данных от сенсоров
CONTROLLER_HTTP_URL = "http://controllers:8080/command"  # URL контроллера

# --- Приём телеметрии по UDP ---
def listen_to_sensors():
    # Создаем UDP-сокет
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", UDP_PORT))
    print(f"[Pilot Interface] Слушаем телеметрию на UDP-порту {UDP_PORT}...")

    while True:
        data, addr = sock.recvfrom(4096)
        try:
            telemetry = json.loads(data.decode("utf-8"))
            print(f"\n[Telemetрия от сенсоров]:")
            for key, value in telemetry.items():
                print(f"  {key}: {value}")
        except json.JSONDecodeError:
            print("[Ошибка] Получены поврежденные данные от сенсоров.")

# --- Отправка команд от пилота контроллерам ---
def send_pilot_command():
    print("[Панель пилота] Автоматическая генерация команд активирована.")
    while True:
        # Случайная команда руления и тяги
        command = {
            "rudder": random.randint(-15, 15),     # Поворот руля (в градусах)
            "throttle": random.randint(40, 100)    # Тяга в процентах
        }

        print(f"\n[Панель пилота] Отправка команды: {command}")
        try:
            response = requests.post(CONTROLLER_HTTP_URL, json=command)
            if response.status_code == 200:
                print("[Pilot Interface] Команда успешно отправлена контроллеру.")
            else:
                print(f"[Pilot Interface] Ошибка: статус {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"[Ошибка сети] Не удалось отправить команду: {e}")

        # Пауза между отправками
        time.sleep(5)  # каждые 5 секунд


# Запускаем оба процесса в отдельных потоках
if __name__ == "__main__":
    threading.Thread(target=listen_to_sensors, daemon=True).start()
    send_pilot_command()  # основной поток — ввод команд
