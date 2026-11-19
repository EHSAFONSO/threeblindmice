# Imagem do tbm. Para escanear a sua LAN, use a rede do host:
#   docker build -t tbm .
#   docker run --rm --network host -v tbm-data:/data tbm scan 192.168.0.0/24 --label casa
# Imagem base fixada por digest (tag + digest): a tag sozinha pode apontar para outra imagem amanhã.
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TBM_HOME=/data \
    PIP_CONFIG_FILE=/app/requirements/pip.conf

WORKDIR /app
COPY requirements ./requirements
# Dependências travadas (versões exatas + hash, só wheels, 3+ dias): ver requirements/pip.conf.
# O pip da imagem pode ser antigo para a política; o bootstrap instala o pip travado antes.
RUN PIP_CONFIG_FILE=/dev/null pip install --no-cache-dir --require-hashes --only-binary :all: --no-deps \
        -r requirements/bootstrap.txt \
    && pip install --no-cache-dir --require-hashes --no-build-isolation -r requirements/runtime.txt
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --no-deps --no-build-isolation . \
    && useradd --create-home --uid 10001 tbm \
    && mkdir -p /data && chown tbm /data

USER tbm
VOLUME ["/data"]
ENTRYPOINT ["tbm"]
CMD ["--help"]
