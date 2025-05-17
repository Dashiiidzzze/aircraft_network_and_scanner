# # # # controllers.py
# # # # Этот скрипт имитирует работу блока управления самолетом.
# # # # Он принимает телеметрию по UDP, обрабатывает данные и отправляет команды исполнительным механизмам.
# # # # Также он предоставляет REST API для получения текущего состояния через HTTP.

# # # import socket              # Для UDP-соединения
# # # import json                # Для работы с данными
# # # import threading           # Для параллельной работы UDP и HTTP
# # # from http.server import BaseHTTPRequestHandler, HTTPServer  # Простой HTTP-сервер

# # # # Конфигурация
# # # UDP_PORT = 5001                    # Порт для приема телеметрии от сенсоров
# # # ACTUATORS_ADDRESS = ("actuators", 5002)  # Адрес исполнительных механизмов (UDP)
# # # HTTP_PORT = 8080                   # Порт HTTP-сервера

# # # # UDP-сокет для приёма данных
# # # udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# # # udp_sock.bind(("", UDP_PORT))

# # # # UDP-сокет для отправки управляющих команд
# # # udp_send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# # # # Храним последние полученные данные
# # # latest_telemetry = {}

# # # def decision_logic(telemetry):
# # #     """
# # #     Простейшая логика принятия решения.
# # #     Возвращает словарь команд для исполнительных механизмов.
# # #     """
# # #     commands = {
# # #         "engine_power": "normal",
# # #         "elevator_angle": 0,
# # #         "rudder_angle": 0,
# # #     }

# # #     # Если слишком низко — увеличить тягу
# # #     if telemetry["altitude"] < 9500:
# # #         commands["engine_power"] = "max"

# # #     # Если есть крен — компенсируем
# # #     if telemetry["roll"] > 10:
# # #         commands["rudder_angle"] = -5
# # #     elif telemetry["roll"] < -10:
# # #         commands["rudder_angle"] = 5

# # #     return commands

# # # def udp_listener():
# # #     """
# # #     Поток для приёма UDP-сообщений от сенсоров
# # #     и отправки команд исполнительным механизмам.
# # #     """
# # #     global latest_telemetry

# # #     while True:
# # #         # Получаем данные
# # #         data, _ = udp_sock.recvfrom(4096)
# # #         telemetry = json.loads(data.decode("utf-8"))

# # #         # Обновляем глобальные данные
# # #         latest_telemetry = telemetry

# # #         # Генерируем команду
# # #         commands = decision_logic(telemetry)

# # #         # Отправляем команды по UDP actuator-ам
# # #         message = json.dumps(commands).encode("utf-8")
# # #         udp_send_sock.sendto(message, ACTUATORS_ADDRESS)

# # # # class ControllerHTTPRequestHandler(BaseHTTPRequestHandler):
# # # #     """
# # # #     HTTP-сервер, выдающий последние данные телеметрии.
# # # #     Используется, например, интерфейсом пилота.
# # # #     """
# # # #     def do_GET(self):
# # # #         if self.path == "/status":
# # # #             self.send_response(200)
# # # #             self.send_header("Content-Type", "application/json")
# # # #             self.end_headers()
# # # #             self.wfile.write(json.dumps(latest_telemetry).encode("utf-8"))
# # # #         else:
# # # #             self.send_response(404)
# # # #             self.end_headers()

# # # def run_http_server():
# # #     """
# # #     Запускаем HTTP-сервер.
# # #     """
# # #     #server = HTTPServer(("", HTTP_PORT), ControllerHTTPRequestHandler)
# # #     print(f"[HTTP] Controller API доступен на порту {HTTP_PORT}")
# # #     #server.serve_forever()

# # # # Запускаем оба потока
# # # threading.Thread(target=udp_listener, daemon=True).start()
# # # run_http_server()



# # # controllers.py
# # # Этот скрипт имитирует работу блока управления самолетом.
# # # Он принимает телеметрию по UDP, обрабатывает данные и отправляет команды исполнительным механизмам.
# # # Также он предоставляет REST API для получения состояния и приёма команд от пилота.

# # import socket
# # import json
# # import threading
# # from http.server import BaseHTTPRequestHandler, HTTPServer

# # # Конфигурация
# # UDP_PORT = 5001
# # ACTUATORS_ADDRESS = ("actuators", 5002)
# # HTTP_PORT = 8080

# # # Сокет для приёма телеметрии
# # udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# # udp_sock.bind(("", UDP_PORT))

# # # Сокет для отправки команд actuator-ам
# # udp_send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# # # Хранилище последних данных
# # latest_telemetry = {}
# # latest_pilot_command = {}  # последние команды от пилота

# # def decision_logic(telemetry, pilot_command=None):
# #     """
# #     Логика принятия решений.
# #     Сочетает данные телеметрии и команды от пилота.
# #     """
# #     commands = {
# #         "engine_power": "normal",
# #         "elevator_angle": 0,
# #         "rudder_angle": 0,
# #     }

# #     # Автономная реакция на высоту и крен
# #     if telemetry.get("altitude", 10000) < 9500:
# #         commands["engine_power"] = "max"

# #     if telemetry.get("roll", 0) > 10:
# #         commands["rudder_angle"] = -5
# #     elif telemetry.get("roll", 0) < -10:
# #         commands["rudder_angle"] = 5

# #     # Если есть команда от пилота — применяем
# #     if pilot_command:
# #         throttle = pilot_command.get("throttle")
# #         rudder = pilot_command.get("rudder")
# #         if throttle is not None:
# #             # Преобразуем числовую тягу в словесную команду
# #             if throttle >= 90:
# #                 commands["engine_power"] = "max"
# #             elif throttle <= 50:
# #                 commands["engine_power"] = "low"
# #             else:
# #                 commands["engine_power"] = "normal"

# #         if rudder is not None:
# #             commands["rudder_angle"] = rudder

# #     return commands

# # def udp_listener():
# #     """
# #     Приём телеметрии от сенсоров и отправка команд actuator-ам.
# #     """
# #     global latest_telemetry

# #     print(f"[UDP] Ожидание телеметрии на порту {UDP_PORT}...")
# #     while True:
# #         data, _ = udp_sock.recvfrom(4096)
# #         telemetry = json.loads(data.decode("utf-8"))
# #         latest_telemetry = telemetry

# #         # Генерация команд с учётом команд от пилота
# #         commands = decision_logic(telemetry, latest_pilot_command)

# #         # Отправка actuator-ам
# #         message = json.dumps(commands).encode("utf-8")
# #         udp_send_sock.sendto(message, ACTUATORS_ADDRESS)

# # class ControllerHTTPRequestHandler(BaseHTTPRequestHandler):
# #     """
# #     HTTP-сервер контроллера: отдаёт телеметрию и принимает команды от пилота.
# #     """

# #     def do_GET(self):
# #         if self.path == "/status":
# #             # Вернуть телеметрию
# #             self.send_response(200)
# #             self.send_header("Content-Type", "application/json")
# #             self.end_headers()
# #             self.wfile.write(json.dumps(latest_telemetry).encode("utf-8"))
# #         else:
# #             self.send_response(404)
# #             self.end_headers()

# #     def do_POST(self):
# #         if self.path == "/command":
# #             content_length = int(self.headers.get("Content-Length", 0))
# #             body = self.rfile.read(content_length)
# #             try:
# #                 command = json.loads(body.decode("utf-8"))
# #                 # Сохраняем команду от пилота
# #                 global latest_pilot_command
# #                 latest_pilot_command = command

# #                 print(f"[HTTP] Получена команда от пилота: {command}")

# #                 self.send_response(200)
# #                 self.end_headers()
# #                 self.wfile.write(b"Command received")
# #             except Exception as e:
# #                 print(f"[Ошибка] Невозможно разобрать команду: {e}")
# #                 self.send_response(400)
# #                 self.end_headers()
# #         else:
# #             self.send_response(404)
# #             self.end_headers()

# # def run_http_server():
# #     """
# #     Запуск HTTP-сервера контроллера.
# #     """
# #     server = HTTPServer(("", HTTP_PORT), ControllerHTTPRequestHandler)
# #     print(f"[HTTP] Controller API доступен на порту {HTTP_PORT}")
# #     server.serve_forever()

# # # Запуск
# # if __name__ == "__main__":
# #     threading.Thread(target=udp_listener, daemon=True).start()
# #     run_http_server()


# import socket
# import json
# import threading
# from http.server import BaseHTTPRequestHandler, HTTPServer

# # Конфигурация
# UDP_PORT = 5001
# ACTUATORS_ADDRESS = ("actuators", 5002)
# AVIONICS_ADDRESS = ("avionics", 5004)  # Добавляем адрес модуля avionics
# HTTP_PORT = 8080

# # Сокет для приёма телеметрии
# udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# udp_sock.bind(("", UDP_PORT))

# # Сокет для отправки команд actuator-ам
# udp_send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# # Сокет для отправки телеметрии в avionics
# avionics_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Новый сокет

# # Хранилище последних данных
# latest_telemetry = {}
# latest_pilot_command = {}  # последние команды от пилота

# def decision_logic(telemetry, pilot_command=None):
#     """
#     Логика принятия решений.
#     Сочетает данные телеметрии и команды от пилота.
#     """
#     commands = {
#         "engine_power": "normal",
#         "elevator_angle": 0,
#         "rudder_angle": 0,
#     }

#     # Автономная реакция на высоту и крен
#     if telemetry.get("altitude", 10000) < 9500:
#         commands["engine_power"] = "max"

#     if telemetry.get("roll", 0) > 10:
#         commands["rudder_angle"] = -5
#     elif telemetry.get("roll", 0) < -10:
#         commands["rudder_angle"] = 5

#     # Если есть команда от пилота — применяем
#     if pilot_command:
#         throttle = pilot_command.get("throttle")
#         rudder = pilot_command.get("rudder")
#         if throttle is not None:
#             if throttle >= 90:
#                 commands["engine_power"] = "max"
#             elif throttle <= 50:
#                 commands["engine_power"] = "low"
#             else:
#                 commands["engine_power"] = "normal"
#         if rudder is not None:
#             commands["rudder_angle"] = rudder

#     return commands

# def udp_listener():
#     """
#     Приём телеметрии от сенсоров и отправка команд actuator-ам и телеметрии в avionics.
#     """
#     global latest_telemetry

#     print(f"[UDP] Ожидание телеметрии на порту {UDP_PORT}...")
#     while True:
#         data, _ = udp_sock.recvfrom(4096)
#         telemetry = json.loads(data.decode("utf-8"))
#         latest_telemetry = telemetry

#         # Генерация команд
#         commands = decision_logic(telemetry, latest_pilot_command)

#         # Отправка actuator-ам
#         message = json.dumps(commands).encode("utf-8")
#         udp_send_sock.sendto(message, ACTUATORS_ADDRESS)

#         # Отправка телеметрии в avionics
#         avionics_data = json.dumps(telemetry).encode("utf-8")
#         avionics_sock.sendto(avionics_data, AVIONICS_ADDRESS)
#         print(f"[UDP] Телеметрия отправлена в avionics: {telemetry}")

# class ControllerHTTPRequestHandler(BaseHTTPRequestHandler):
#     """
#     HTTP-сервер контроллера: отдаёт телеметрию и принимает команды от пилота.
#     """
#     def do_GET(self):
#         if self.path == "/status":
#             self.send_response(200)
#             self.send_header("Content-Type", "application/json")
#             self.end_headers()
#             self.wfile.write(json.dumps(latest_telemetry).encode("utf-8"))
#         else:
#             self.send_response(404)
#             self.end_headers()

#     def do_POST(self):
#         if self.path == "/command":
#             content_length = int(self.headers.get("Content-Length", 0))
#             body = self.rfile.read(content_length)
#             try:
#                 command = json.loads(body.decode("utf-8"))
#                 global latest_pilot_command
#                 latest_pilot_command = command

#                 print(f"[HTTP] Получена команда от пилота: {command}")

#                 self.send_response(200)
#                 self.end_headers()
#                 self.wfile.write(b"Command received")
#             except Exception as e:
#                 print(f"[Ошибка] Невозможно разобрать команду: {e}")
#                 self.send_response(400)
#                 self.end_headers()
#         else:
#             self.send_response(404)
#             self.end_headers()

# def run_http_server():
#     """
#     Запуск HTTP-сервера контроллера.
#     """
#     server = HTTPServer(("", HTTP_PORT), ControllerHTTPRequestHandler)
#     print(f"[HTTP] Controller API доступен на порту {HTTP_PORT}")
#     server.serve_forever()

# # Запуск
# if __name__ == "__main__":
#     threading.Thread(target=udp_listener, daemon=True).start()
#     run_http_server()


import socket
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

# Конфигурация
UDP_PORT = 5001  # порт, на котором принимается телеметрия от sensors
ACTUATORS_ADDRESS = ("actuators", 5002)  # адрес для отправки команд actuator-ам
AVIONICS_ADDRESS = ("avionics", 5004)    # адрес для отправки данных в avionics
HTTP_PORT = 8080  # порт HTTP API

# Только эти поля будут переданы в avionics
ALLOWED_FIELDS = {"altitude", "speed", "status"}

# Сокет для приёма телеметрии
udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_sock.bind(("", UDP_PORT))

# Сокеты для отправки:
udp_send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # actuator-ы
udp_avionics_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # avionics

# Хранилище последних данных
latest_telemetry = {}
latest_pilot_command = {}  # последние команды от пилота

def decision_logic(telemetry, pilot_command=None):
    """
    Логика принятия решений.
    Сочетает данные телеметрии и команды от пилота.
    """
    commands = {
        "engine_power": "normal",
        "elevator_angle": 0,
        "rudder_angle": 0,
    }

    # Автономная реакция на высоту и крен
    if telemetry.get("altitude", 10000) < 9500:
        commands["engine_power"] = "max"

    if telemetry.get("roll", 0) > 10:
        commands["rudder_angle"] = -5
    elif telemetry.get("roll", 0) < -10:
        commands["rudder_angle"] = 5

    # Если есть команда от пилота — применяем
    if pilot_command:
        throttle = pilot_command.get("throttle")
        rudder = pilot_command.get("rudder")
        if throttle is not None:
            if throttle >= 90:
                commands["engine_power"] = "max"
            elif throttle <= 50:
                commands["engine_power"] = "low"
            else:
                commands["engine_power"] = "normal"

        if rudder is not None:
            commands["rudder_angle"] = rudder

    return commands

def udp_listener():
    """
    Приём телеметрии от сенсоров и отправка команд actuator-ам.
    Также фильтрация и отправка части данных в модуль avionics.
    """
    global latest_telemetry

    print(f"[UDP] Ожидание телеметрии на порту {UDP_PORT}...")
    while True:
        data, _ = udp_sock.recvfrom(4096)
        telemetry = json.loads(data.decode("utf-8"))
        latest_telemetry = telemetry

        # Генерация команд с учётом команд от пилота
        commands = decision_logic(telemetry, latest_pilot_command)

        # Отправка команд actuator-ам
        message = json.dumps(commands).encode("utf-8")
        udp_send_sock.sendto(message, ACTUATORS_ADDRESS)

        # Отправка только разрешённых полей телеметрии в avionics
        avionics_payload = {
            key: telemetry[key] for key in ALLOWED_FIELDS if key in telemetry
        }
        if avionics_payload:
            udp_avionics_sock.sendto(
                json.dumps(avionics_payload).encode("utf-8"), AVIONICS_ADDRESS
            )
            print(f"[AVIONICS] Отправлены данные: {avionics_payload}")

class ControllerHTTPRequestHandler(BaseHTTPRequestHandler):
    """
    HTTP-сервер контроллера: отдаёт телеметрию и принимает команды от пилота.
    """

    def do_GET(self):
        if self.path == "/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(latest_telemetry).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/command":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            try:
                command = json.loads(body.decode("utf-8"))
                global latest_pilot_command
                latest_pilot_command = command

                print(f"[HTTP] Получена команда от пилота: {command}")

                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Command received")
            except Exception as e:
                print(f"[Ошибка] Невозможно разобрать команду: {e}")
                self.send_response(400)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

def run_http_server():
    """
    Запуск HTTP-сервера контроллера.
    """
    server = HTTPServer(("", HTTP_PORT), ControllerHTTPRequestHandler)
    print(f"[HTTP] Controller API доступен на порту {HTTP_PORT}")
    server.serve_forever()

# Запуск
if __name__ == "__main__":
    threading.Thread(target=udp_listener, daemon=True).start()
    run_http_server()
