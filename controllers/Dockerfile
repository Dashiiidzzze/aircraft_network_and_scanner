# Dockerfile
# Контейнер для блока контроллеров

FROM python:3.10-slim

WORKDIR /app

COPY controllers.py .
ENV PYTHONUNBUFFERED=1
CMD ["python", "controllers.py"]
