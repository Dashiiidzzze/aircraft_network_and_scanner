# Dockerfile
# Контейнер для интерфейса пилота

FROM python:3.10-slim

WORKDIR /app

# Устанавливаем зависимости
RUN pip install requests

# Копируем код
COPY pilot_interface.py .
ENV PYTHONUNBUFFERED=1
# Запуск
CMD ["python", "pilot_interface.py"]
