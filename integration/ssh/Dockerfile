FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
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
