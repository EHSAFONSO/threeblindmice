FROM nginx:1.25-alpine@sha256:516475cc129da42866742567714ddc681e5eed7b9ee0b9e9c015e464b4221a00
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY html/ /usr/share/nginx/html/
# A imagem traz um index.html ("Welcome to nginx"); com ele presente, GET / devolve
# essa página e o autoindex nunca aparece. Removemos para expor a listagem.
RUN rm -f /usr/share/nginx/html/index.html
# Repositório .git "esquecido" no deploy: alvo do check http.paths.
# (Criado aqui porque o git não versiona diretórios chamados .git.)
RUN mkdir -p /usr/share/nginx/html/.git \
    && echo "ref: refs/heads/main" > /usr/share/nginx/html/.git/HEAD
