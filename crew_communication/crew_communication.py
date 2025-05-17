# crew_communication.py
# Система связи экипажа — принимает и обрабатывает данные от безопасного шлюза

from flask import Flask, request, jsonify
import logging

app = Flask(__name__)

# Настройка логгирования
logging.basicConfig(level=logging.INFO)

# Хранилище принятых сообщений
received_data = []

# Эндпоинт для приёма данных от безопасного шлюза
@app.route("/receive", methods=["POST"])
def receive_data():
    data = request.get_json()

    if not data:
        logging.warning("[CrewComm] Получен пустой JSON.")
        return jsonify({"error": "No data"}), 400

    # Добавление данных в журнал
    received_data.append(data)
    logging.info(f"[CrewComm] Приняты данные: {data}")

    return jsonify({"status": "Received"}), 200

# Эндпоинт для просмотра принятых сообщений (например, через curl)
@app.route("/log", methods=["GET"])
def get_log():
    return jsonify(received_data), 200

# Запуск сервера
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8084)
