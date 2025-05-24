FROM python:3.10-slim

WORKDIR /app

RUN pip install requests

COPY avionics.py .
ENV PYTHONUNBUFFERED=1
CMD ["python", "avionics.py"]
