# Dockerfile
# Контейнер для исполнительных механизмов

FROM python:3.10-slim

WORKDIR /app

COPY actuators.py .
ENV PYTHONUNBUFFERED=1
CMD ["python", "actuators.py"]
