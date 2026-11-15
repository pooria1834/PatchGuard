FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp
RUN apt-get update && apt-get install -y --no-install-recommends     build-essential binutils file git make cmake     && rm -rf /var/lib/apt/lists/*     && groupadd --gid 1000 pg     && useradd --uid 1000 --gid 1000 --create-home --home-dir /home/pg pg
WORKDIR /work
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
USER pg
