FROM python:3.10-slim

# Instructing python not to write byte code
ENV PYTHONDONTWRITEBYTECODE=1
# Instructing python to put logs(success/error) instantly don't put it in buffer
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# build-essential :- It's C compiler used to compile some python cryptography package as it's written in c
# libssl-dev:- Used for SSL/TLS/HTTPS used during JWT signing, Supabase, etc
# libffi-dev:- It helps python to communicate with C library used in cryptography
# curl:- Used for making api calls for health check and debigging
# /var/lib/apt/lists/* :- It's list of names of all packages that we have download , no need to keep the list so delete it..

RUN apt-get update && apt-get install -y build-essential libssl-dev libffi-dev curl && rm -rf /var/lib/apt/lists/*


RUN pip install --no-cache-dir poetry

COPY pyproject.toml poetry.lock* ./

RUN poetry config virtualenvs.create false \
    && poetry install --no-root --no-interaction --no-ansi

COPY app ./app

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]