# vsftpd com login anônimo (alvo do check service.ftp-anon).
#
# isolate/isolate_network=NO: por padrão o vsftpd cria namespaces novos a cada
# sessão (clone com CLONE_NEWNET/NEWPID). Sem CAP_SYS_ADMIN no container, isso
# falha e o processo morre com segfault (exit 139) na primeira conexão.
#
# Atenção: este é o vsftpd upstream (Alpine). Opções de patches de distro, como
# o reverse_lookup_enable do Red Hat, fazem ele sair com código 2 sem mensagem.
FROM alpine:3.20
RUN apk add --no-cache vsftpd \
    && mkdir -p /var/ftp/pub /var/run/vsftpd/empty \
    && printf '%s\n' \
       "listen=YES" \
       "background=NO" \
       "isolate=NO" \
       "isolate_network=NO" \
       "anonymous_enable=YES" \
       "local_enable=NO" \
       "anon_root=/var/ftp" \
       "no_anon_password=YES" \
       "seccomp_sandbox=NO" \
       "pasv_enable=YES" \
       "pasv_min_port=21100" \
       "pasv_max_port=21110" \
       "secure_chroot_dir=/var/run/vsftpd/empty" \
       "log_ftp_protocol=YES" \
       "syslog_enable=NO" \
       "vsftpd_log_file=/var/log/vsftpd.log" \
       > /etc/vsftpd/vsftpd.conf
EXPOSE 21
# O log vai para um arquivo (o vsftpd faz lock nele, o que não funciona num pipe)
# e o tail o espelha no stdout do container, para aparecer no `docker compose logs`.
CMD ["sh", "-c", "touch /var/log/vsftpd.log && (tail -F /var/log/vsftpd.log &) && exec vsftpd /etc/vsftpd/vsftpd.conf"]
