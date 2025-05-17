# Dockerfile
# Контейнер безопасного шлюза

FROM python:3.10-slim

WORKDIR /app

RUN pip install flask requests

COPY secure_gateway.py .

EXPOSE 8090
ENV PYTHONUNBUFFERED=1
CMD ["python", "secure_gateway.py"]
