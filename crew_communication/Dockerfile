#FROM python:3.10-slim
FROM python:latest
WORKDIR /app

RUN pip install flask

COPY crew_communication.py .

EXPOSE 8081
ENV PYTHONUNBUFFERED=1
CMD ["python", "crew_communication.py"]
