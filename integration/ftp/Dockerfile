# Servidor FTP com login anônimo (alvo do check service.ftp-anon).
#
# Usamos o pyftpdlib em vez do vsftpd: o vsftpd do Alpine dava segfault
# (exit 139) de forma intermitente dentro do container, mesmo com
# isolate=NO/seccomp_sandbox=NO. O pyftpdlib fala FTP de verdade, aceita
# USER anonymous por padrão (somente leitura) e não depende de namespaces.
# Combinação validada localmente: Python 3.12 + pyftpdlib 1.5.10.
FROM python:3.12-alpine
RUN pip install --no-cache-dir pyftpdlib==1.5.10 \
    && mkdir -p /srv/ftp/pub \
    && echo "arquivo público do laboratório" > /srv/ftp/pub/LEIAME.txt
EXPOSE 21
CMD ["python", "-m", "pyftpdlib", "--port", "21", "--interface", "0.0.0.0", "--directory", "/srv/ftp"]
