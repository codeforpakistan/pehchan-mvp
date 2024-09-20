FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml poetry.lock* ./

RUN pip install poetry && \
    poetry config virtualenvs.create false && \
    poetry lock --no-update && \
    poetry install --no-dev

COPY . .

EXPOSE 5002

CMD ["python", "main.py"]