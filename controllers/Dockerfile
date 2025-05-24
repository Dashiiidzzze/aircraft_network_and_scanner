FROM python:3.10-slim

WORKDIR /app

RUN mkdir /app/certs
COPY certs /app/certs

COPY controllers.py .
ENV PYTHONUNBUFFERED=1
CMD ["python", "controllers.py"]
