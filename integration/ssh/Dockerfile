FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
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
