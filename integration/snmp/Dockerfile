FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
RUN apk add --no-cache net-snmp \
    && printf '%s\n' \
       "agentaddress udp:161" \
       "rocommunity public default" \
       "sysdescr threeblindmice-lab-snmp" \
       > /etc/snmp/snmpd.conf
EXPOSE 161/udp
CMD ["snmpd", "-f", "-Lo", "-C", "-c", "/etc/snmp/snmpd.conf"]
