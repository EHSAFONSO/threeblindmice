# 🐭🐭🐭 threeblindmice

Toolkit **defensivo** de avaliação de segurança para redes e serviços que você controla.
São três "mice" que trabalham em sequência:

| Mouse | Papel | O que faz |
|---|---|---|
| **Scout** | Reconhecimento | Descobre hosts (TCP ping), varre portas (connect scan assíncrono), faz banner grabbing e fingerprint de serviços e coleta certificados TLS |
| **Sniffer** | Análise | Roda checks plugáveis: serviços de risco expostos, Redis sem senha, TLS fraco ou expirado, headers HTTP, cookies, CVEs via NVD (com destaque para o CISA KEV), segredos em código e, com `--active`, FTP anônimo, `.git`/`.env` expostos e APIs abertas |
| **Squeak** | Comunicação | Dá uma nota de risco de 0 a 100 (A a F), guarda o histórico em SQLite, compara com o scan anterior ("o que mudou?"), gera relatório HTML e alerta via webhook (Discord, Slack ou genérico) |

> ⚠️ Use somente em sistemas que são seus ou que você tem autorização por escrito para testar.
> Por padrão, o tbm **recusa** qualquer alvo fora das redes privadas.

## Instalação

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows  (Linux/macOS: source .venv/bin/activate)
pip install -e ".[dev]"
```

## Uso

```bash
# Os três juntos: rede de casa, com rótulo para o histórico
tbm scan 192.168.0.0/24 --label casa

# Mais fundo: checks ativos e todas as portas, num host só
tbm scan 192.168.0.10 -p all --active --label nas

# Seu VPS (IP público): exige scope.yaml com authorized: true
copy scope.example.yaml scope.yaml
tbm scan 203.0.113.10 --scope scope.yaml --label vps --active

# Também varre segredos num repositório local
tbm scan 127.0.0.1 --secrets C:\dev\meu-projeto

# Em etapas (bom para estudar cada mouse separadamente)
tbm scout 192.168.0.0/24 -o scout.json
tbm sniff scout.json --active
tbm report-file scout.json -o relatorio.html

# Só segredos (sai com código 1 se achar algo: dá para usar em pre-commit/CI)
tbm secrets .

# Histórico e diff
tbm history
tbm diff <scan_id_antigo> <scan_id_novo>
tbm report <scan_id> -o relatorio.html

# Alertas
tbm scan 192.168.0.0/24 -l casa --notify https://discord.com/api/webhooks/...
tbm scan ... --fail-on high          # código de saída 1 se houver HIGH+ (CI)

tbm checks                           # lista os checks registrados
```

Variáveis de ambiente:

- `NVD_API_KEY`: chave gratuita do NVD; sobe o limite de 5 para 50 requisições a cada 30s ([pedir aqui](https://nvd.nist.gov/developers/request-an-api-key)).
- `TBM_WEBHOOK`: webhook padrão para alertas.
- `TBM_HOME`: onde ficam o histórico e o cache (padrão: `~/.threeblindmice`).

## Arquitetura

```
src/tbm/
├── models.py          # Host, Service, TLSInfo, Finding, ScanResult (pydantic)
├── scope.py           # allowlist, expansão de CIDR/faixas/hostnames
├── asyncutil.py       # gather_limited (pool de workers) e RateLimiter
├── pipeline.py        # Scout → Sniffer → nota
├── cli.py             # Typer + Rich
├── scout/
│   ├── portscan.py    # connect scan, TCP ping, DNS reverso
│   ├── banner.py      # sondas por porta + assinaturas regex
│   ├── tls.py         # certificado (cryptography), TLS 1.0/1.1 legados
│   └── engine.py
├── sniffer/
│   ├── base.py        # Check, CheckContext, @register
│   ├── service_checks.py, tls_checks.py, http_checks.py
│   ├── cve.py         # cliente NVD 2.0 com cache e rate limit
│   ├── secrets.py     # regex + entropia de Shannon
│   └── engine.py
└── squeak/
    ├── scoring.py     # nota com decaimento exponencial
    ├── store.py       # SQLite
    ├── diff.py        # fingerprints estáveis → novo/resolvido/persistente
    ├── report.py + templates/report.html.j2
    └── notify.py
```

### Decisões de design que valem estudar

- **Connect scan em vez de SYN scan:** não precisa de admin nem do Npcap, e funciona igual em qualquer SO. A concorrência fica em `asyncio` com um semáforo global de sockets.
- **`gather_limited`:** recebe *fábricas* de corrotinas, não corrotinas. Um /16 com 65535 portas daria ~4 bilhões de objetos; com o pool, só existem `limit` corrotinas vivas por vez.
- **Fingerprint estável dos achados:** `sha1(check_id|host|port|key)`. É o que permite ao diff dizer "este achado é o mesmo do mês passado" mesmo que a severidade ou o texto mudem.
- **Validação de conteúdo nos checks ativos:** `/.env` só conta se o corpo parece mesmo um `.env`. Muitos servidores devolvem 200 para tudo ("soft 404").
- **CVEs por versão são "potenciais":** distros fazem backport de patches sem mudar a versão do banner.
- **Nota exponencial:** `100·e^(−penalidade/80)`. O primeiro crítico pesa muito e o décimo LOW quase nada.

### Escrevendo um check novo

```python
# src/tbm/sniffer/meu_check.py
from tbm.models import Finding, Severity
from tbm.sniffer.base import Check, CheckContext, register

@register
class SNMPDefaultCheck(Check):
    id = "service.exemplo"
    name = "Meu check"
    active_only = False

    async def run(self, ctx: CheckContext) -> list[Finding]:
        out = []
        for host, svc in ctx.services(lambda s: s.port == 8080):
            out.append(Finding(check_id=self.id, title="...", severity=Severity.LOW,
                               host=host.address, port=svc.port))
        return out
```

Depois, importe o módulo em `sniffer/engine.py` para registrar.

## Testes

```bash
pytest -q
```

Os testes não usam rede externa: servidores falsos sobem em `127.0.0.1`, as respostas HTTP vêm via `httpx` e os certificados são gerados na hora.

## Roadmap

- [ ] Varredura UDP (DNS, SNMP, mDNS, SSDP)
- [ ] Fingerprint de SO por TTL e comportamento TCP
- [ ] Checks de SSH (algoritmos fracos via KEXINIT)
- [ ] Dashboard web (FastAPI + HTMX) lendo o histórico
- [ ] Agendamento (scan diário com alerta só do que mudou)
