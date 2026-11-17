FROM alpine:3.20
RUN apk add --no-cache vsftpd \
    && mkdir -p /var/ftp/pub /var/run/vsftpd/empty \
    && printf '%s\n' \
       "listen=YES" \
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
