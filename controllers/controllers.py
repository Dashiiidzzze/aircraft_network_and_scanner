# Этот скрипт имитирует работу блока управления самолетом.
# Он принимает телеметрию по UDP, обрабатывает данные и отправляет команды исполнительным механизмам.
# Также он предоставляет REST API для получения текущего состояния через HTTP.

import socket
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl

UDP_PORT = 5001  # порт, на котором принимается телеметрия от sensors
ACTUATORS_ADDRESS = ("actuators.critical.local", 5002)  # адрес для отправки команд actuator-ам
AVIONICS_ADDRESS = ("avionics.critical.local", 5004)    # адрес для отправки данных в avionics
HTTP_PORT = 8080  # порт HTTP API

# Только эти поля будут переданы в avionics
ALLOWED_FIELDS = {"altitude", "speed", "status"}

# Сокет для приёма телеметрии
udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_sock.bind(("", UDP_PORT))

# Сокеты для отправки:
udp_send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # actuator
udp_avionics_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # avionics

# Хранилище последних данных
latest_telemetry = {}
latest_pilot_command = {}  # последние команды от пилота

# Логика принятия решений. Сочетает данные телеметрии и команды от пилота.
def decision_logic(telemetry, pilot_command=None):
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

# Приём телеметрии от сенсоров и отправка команд actuator-ам.
# Также фильтрация и отправка части данных в модуль avionics.
def udp_listener():
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

# HTTP-сервер контроллера: отдаёт телеметрию и принимает команды от пилота.
class ControllerHTTPRequestHandler(BaseHTTPRequestHandler):
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

# Запуск HTTP-сервера контроллера.
def run_http_server():
    # HTTP
    # server = HTTPServer(("", HTTP_PORT), ControllerHTTPRequestHandler)
    # print(f"[HTTP] Controller API доступен на порту {HTTP_PORT}")
    # server.serve_forever()

    # HTTPS
    server_address = ("", HTTP_PORT)
    httpd = HTTPServer(server_address, ControllerHTTPRequestHandler)

    # Обёртка SSL (TLS) вокруг обычного сокета
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="certs/cert.pem", keyfile="certs/key.pem")
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print(f"[HTTPS] Controller API доступен на порту {HTTP_PORT} через HTTPS")
    httpd.serve_forever()


if __name__ == "__main__":
    threading.Thread(target=udp_listener, daemon=True).start()
    run_http_server()
