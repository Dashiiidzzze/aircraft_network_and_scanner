FROM python:3.10-slim

WORKDIR /app

RUN pip install requests

RUN mkdir /app/certs
#COPY certs /app/certs

COPY pilot_interface.py .
ENV PYTHONUNBUFFERED=1

CMD ["python", "pilot_interface.py"]
