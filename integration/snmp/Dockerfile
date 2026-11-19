FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
RUN apk add --no-cache net-snmp \
    && printf '%s\n' \
       "agentaddress udp:161" \
       "rocommunity public default" \
       "sysdescr threeblindmice-lab-snmp" \
       > /etc/snmp/snmpd.conf
EXPOSE 161/udp
CMD ["snmpd", "-f", "-Lo", "-C", "-c", "/etc/snmp/snmpd.conf"]
