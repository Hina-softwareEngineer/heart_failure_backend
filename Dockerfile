FROM python:3.7-slim-buster

ENV PORT 8000

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

EXPOSE 8000

COPY . .

CMD ["python", "main.py"]