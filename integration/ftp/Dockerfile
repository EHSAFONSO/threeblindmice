# isolate/isolate_network=NO: por padrão o vsftpd cria namespaces novos a cada
# sessão (clone com CLONE_NEWNET/NEWPID). Sem CAP_SYS_ADMIN no container, isso
# falha e o processo morre com segfault (exit 139) na primeira conexão.
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
       > /etc/vsftpd/vsftpd.conf
EXPOSE 21
CMD ["vsftpd", "/etc/vsftpd/vsftpd.conf"]
