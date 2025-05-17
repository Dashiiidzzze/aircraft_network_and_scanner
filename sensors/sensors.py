# sensors.py
# Этот скрипт имитирует работу бортовых сенсоров самолёта.
# Он с заданным интервалом (например, 1 секунда) генерирует случайные данные о параметрах полёта
# и рассылает их по UDP на два получателя: контроллеры и интерфейс пилота.

import socket         # Для отправки UDP-пакетов
import time           # Для паузы между отправками
import json           # Для сериализации данных
import random         # Для генерации случайных телеметрических данных

# Настройка адресов получателей
CONTROLLERS_ADDRESS = ("controllers", 5001)       # Контейнер "controllers", порт 5001
PILOT_INTERFACE_ADDRESS = ("pilot_interface", 5003)  # Контейнер "pilot_interface", порт 5003

# Создаём UDP-сокет
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def generate_telemetry():
    """
    Генерация набора телеметрических данных.
    Здесь мы создаём случайные, но реалистичные значения параметров полёта.
    """
    return {
        "altitude": round(random.uniform(9000, 12000), 2),     # Высота (метры)
        "speed": round(random.uniform(200, 900), 2),           # Скорость (км/ч)
        "temperature": round(random.uniform(-60, 10), 2),      # Температура (°C)
        "pitch": round(random.uniform(-10, 10), 2),            # Тангаж
        "roll": round(random.uniform(-30, 30), 2),             # Крен
        "yaw": round(random.uniform(0, 360), 2),               # Курсовой угол
    }
time.sleep(5)
while True:
    # Генерируем телеметрию
    telemetry = generate_telemetry()

    # Преобразуем в строку JSON
    message = json.dumps(telemetry).encode('utf-8')

    # Отправляем UDP-пакет контроллерам
    sock.sendto(message, CONTROLLERS_ADDRESS)

    # Отправляем UDP-пакет интерфейсу пилота
    sock.sendto(message, PILOT_INTERFACE_ADDRESS)

    # Ждём 1 секунду до следующей отправки
    time.sleep(5)
