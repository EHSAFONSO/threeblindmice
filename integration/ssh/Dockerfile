FROM alpine:3.20
RUN apk add --no-cache openssh \
    && ssh-keygen -A \
    && printf '%s\n' \
       "PasswordAuthentication yes" \
       "KbdInteractiveAuthentication yes" \
       "Ciphers aes128-cbc,aes256-ctr,aes128-gcm@openssh.com" \
       > /etc/ssh/sshd_config.d/lab.conf \
    && adduser -D labuser && echo "labuser:labpass" | chpasswd
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
