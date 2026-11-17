"""Checks sobre serviços UDP encontrados pelo Scout.

O contexto muda a severidade: um resolver DNS recursivo na sua LAN é normal
(é o roteador), mas na internet vira arma de DDoS por amplificação.
"""

from __future__ import annotations

from tbm.models import Finding, Severity
from tbm.scope import is_public
from tbm.sniffer.base import Check, CheckContext, register


@register
class UDPServicesCheck(Check):
    id = "udp.services"
    name = "Serviços UDP (DNS, SNMP, SSDP, mDNS, NTP)"

    async def run(self, ctx: CheckContext) -> list[Finding]:
        out: list[Finding] = []
        for host, svc in ctx.services(transport="udp"):
            public = is_public(host.address)

            def add(key: str, sev: Severity, title: str, desc: str, evidence: str, fix: str,
                    host=host, svc=svc) -> None:
                out.append(Finding(check_id=self.id, key=key, severity=sev, title=title,
                                   host=host.address, port=svc.port, transport="udp",
                                   description=desc, evidence=evidence, remediation=fix))

            if svc.name == "snmp":
                add("snmp-public", Severity.HIGH, "SNMP responde à community 'public'",
                    "A community padrão expõe a configuração completa do dispositivo (interfaces, "
                    "rotas, processos, às vezes credenciais). Em equipamentos com 'private' "
                    "padrão, dá até para alterar a configuração.",
                    f"sysDescr: {svc.extra.get('sysdescr', '')}",
                    "Desative o SNMP v1/v2c ou troque a community. Prefira SNMPv3 com authPriv.")
            elif svc.name == "dns" and svc.extra.get("recursion") == "yes" and public:
                add("open-resolver", Severity.MEDIUM, "Resolver DNS aberto na internet",
                    "Resolvers recursivos abertos são usados em ataques de amplificação DDoS e "
                    "facilitam cache poisoning.",
                    "Resolveu example.com com o bit RA ligado",
                    "Restrinja a recursão aos seus clientes (allow-recursion no BIND, "
                    "access-control no Unbound).")
            elif svc.name == "ssdp":
                add("ssdp", Severity.HIGH if public else Severity.LOW,
                    "UPnP/SSDP exposto à internet" if public else "UPnP/SSDP ativo",
                    "O UPnP deixa qualquer programa da rede abrir portas no roteador sem pedir "
                    "permissão (malwares usam isso), e o SSDP público amplifica DDoS.",
                    " · ".join(f"{k}: {v}" for k, v in svc.extra.items()),
                    "Desative o UPnP no roteador se não precisar dele.")
            elif svc.name == "mdns" and public:
                add("mdns", Severity.MEDIUM, "mDNS exposto à internet",
                    "O mDNS na internet vaza nomes e serviços internos e serve para amplificação.",
                    svc.extra.get("services", ""), "Bloqueie a UDP/5353 na borda.")
            elif svc.name == "mdns" and svc.extra.get("services"):
                add("mdns", Severity.INFO, "Serviços anunciados via mDNS",
                    "Inventário: o que este dispositivo anuncia na rede local.",
                    svc.extra["services"], "Nada a fazer se os serviços são esperados.")
            elif svc.name == "ntp" and public:
                add("ntp", Severity.LOW, "NTP exposto à internet",
                    "Servidores NTP públicos mal configurados (monlist) já foram usados em DDoS.",
                    f"NTP v{svc.extra.get('version')} stratum {svc.extra.get('stratum')}",
                    "Use 'restrict default noquery' e desative o monlist.")
        return out
