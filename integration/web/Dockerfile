FROM nginx:1.25-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY html/ /usr/share/nginx/html/
# A imagem traz um index.html ("Welcome to nginx"); com ele presente, GET / devolve
# essa página e o autoindex nunca aparece. Removemos para expor a listagem.
RUN rm -f /usr/share/nginx/html/index.html
# Repositório .git "esquecido" no deploy: alvo do check http.paths.
# (Criado aqui porque o git não versiona diretórios chamados .git.)
RUN mkdir -p /usr/share/nginx/html/.git \
    && echo "ref: refs/heads/main" > /usr/share/nginx/html/.git/HEAD
