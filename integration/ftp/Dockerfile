# Servidor FTP com login anônimo (alvo do check service.ftp-anon).
#
# Usamos o pyftpdlib em vez do vsftpd: o vsftpd do Alpine dava segfault
# (exit 139) de forma intermitente dentro do container, mesmo com
# isolate=NO/seccomp_sandbox=NO. O pyftpdlib fala FTP de verdade, aceita
# USER anonymous por padrão (somente leitura) e não depende de namespaces.
# Combinação validada localmente: Python 3.12 + pyftpdlib 1.5.10.
# Só para o laboratório do CI (nunca vai para a imagem publicada). O pyftpdlib
# não tem wheel: fica travado pelo hash do sdist publicado em 2024.
FROM python:3.12-alpine@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89
RUN echo "pyftpdlib==1.5.10 --hash=sha256:8dbdeb1215bcba2fb748dae31ffdb1ab008540c28d13b3704e178f368a087128" \
        > /tmp/lab-requirements.txt \
    && pip install --no-cache-dir --require-hashes -r /tmp/lab-requirements.txt \
    && mkdir -p /srv/ftp/pub \
    && echo "arquivo público do laboratório" > /srv/ftp/pub/LEIAME.txt
EXPOSE 21
CMD ["python", "-m", "pyftpdlib", "--port", "21", "--interface", "0.0.0.0", "--directory", "/srv/ftp"]
