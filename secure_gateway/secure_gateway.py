# Безопасный шлюз между критическим и информационным доменами

from flask import Flask, request, jsonify
import requests
import logging

app = Flask(__name__)

CREW_COMM_URL = "http://crew.info.local:8084/receive"  # урл для отправки в crew_communication
ALLOWED_FIELDS = {"altitude", "speed", "status"}  # Допустимые ключи

# Настройка логированияs
logging.basicConfig(level=logging.INFO)

# Фильтрация и переадресация
@app.route("/ingest", methods=["POST"])
def ingest():
    data = request.get_json()

    if not data:
        logging.warning("[Gateway] Получен пустой или невалидный JSON.")
        return jsonify({"error": "Invalid JSON"}), 400

    # Проверка: только допустимые ключи
    if not all(key in ALLOWED_FIELDS for key in data):
        logging.warning(f"[Gateway] Обнаружены недопустимые поля: {list(data.keys())}")
        return jsonify({"error": "Forbidden fields"}), 403

    try:
        # Отправка в информационный домен
        resp = requests.post(CREW_COMM_URL, json=data, verify=False)
        if resp.status_code == 200:
            logging.info("[Gateway] Данные успешно переданы системе экипажа.")
            return jsonify({"status": "OK"}), 200
        else:
            logging.error(f"[Gateway] Сбой отправки в CrewComm: {resp.status_code}")
            return jsonify({"error": "Forwarding failed"}), 502

    except Exception as e:
        logging.error(f"[Gateway] Исключение при отправке: {e}")
        return jsonify({"error": "Internal error"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8083)