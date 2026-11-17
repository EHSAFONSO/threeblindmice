# Imagem do tbm. Para escanear a sua LAN, use a rede do host:
#   docker build -t tbm .
#   docker run --rm --network host -v tbm-data:/data tbm scan 192.168.0.0/24 --label casa
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TBM_HOME=/data

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir ".[web]" \
    && useradd --create-home --uid 10001 tbm \
    && mkdir -p /data && chown tbm /data

USER tbm
VOLUME ["/data"]
ENTRYPOINT ["tbm"]
CMD ["--help"]
