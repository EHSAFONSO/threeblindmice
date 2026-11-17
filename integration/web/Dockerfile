FROM nginx:1.25-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY html/ /usr/share/nginx/html/
# Repositório .git "esquecido" no deploy: alvo do check http.paths.
# (Criado aqui porque o git não versiona diretórios chamados .git.)
RUN mkdir -p /usr/share/nginx/html/.git \
    && echo "ref: refs/heads/main" > /usr/share/nginx/html/.git/HEAD
