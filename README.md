# 🐭🐭🐭 threeblindmice

Toolkit **defensivo** de avaliação de segurança para redes e serviços que você controla.
São três "mice" que trabalham em sequência:

| Mouse | Papel | O que faz |
|---|---|---|
| **Scout** | Reconhecimento | Descobre hosts (TCP ping), varre portas TCP (connect scan assíncrono) e UDP (sondas de DNS, NTP, SNMP, SSDP e mDNS), faz fingerprint de serviços, coleta certificados TLS e identifica o MAC e o fabricante de cada dispositivo |
| **Sniffer** | Análise | Tem 13 checks plugáveis: serviços de risco, Redis sem senha, SMBv1 e signing, algoritmos SSH e Terrapin, TLS, headers HTTP, UDP exposto, CVEs (NVD) priorizados por **CISA KEV + EPSS** com filtro de **backport da distro**, e segredos em código. Com `--active`: FTP anônimo, métodos de auth SSH, `.git`/`.env` expostos e APIs abertas |
| **Squeak** | Comunicação | Dá uma nota de 0 a 100 (A a F) ponderada pela probabilidade real de exploração, guarda o histórico em SQLite, compara com o scan anterior (dispositivos novos, portas, MAC trocado), gera relatório HTML/JSON/SARIF, envia alertas por webhook e oferece um dashboard web |

> ⚠️ Use somente em sistemas que são seus ou que você tem autorização por escrito para testar.
> Por padrão, o tbm **recusa** qualquer alvo fora das redes privadas.

## Instalação

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows  (Linux/macOS: source .venv/bin/activate)
pip install -e ".[dev]"          # ou ".[web]" só para o dashboard, ou "." para o básico
tbm update-oui                   # opcional: base de fabricantes de placas de rede (IEEE, ~3 MB)
```

## Uso

```bash
# Os três juntos: rede de casa, com UDP e rótulo para o histórico
tbm scan 192.168.0.0/24 --label casa --udp

# Mais fundo: checks ativos e todas as portas, num host só
tbm scan 192.168.0.10 -p all --active --label nas

# Seu VPS (IP público): exige scope.yaml com authorized: true
copy scope.example.yaml scope.yaml
tbm scan 203.0.113.10 --scope scope.yaml --label vps --active

# Vigia: repete a cada 6h e só alerta quando algo muda
tbm watch 192.168.0.0/24 --label casa --every 6h --notify https://discord.com/api/webhooks/...

# Dashboard (somente leitura, em 127.0.0.1)
tbm dashboard

# Em etapas (bom para estudar cada mouse separadamente)
tbm scout 192.168.0.0/24 --udp -o scout.json
tbm sniff scout.json --active        # os hosts do JSON são revalidados contra o escopo
tbm report-file scout.json -o relatorio.html

# Segredos: pre-commit, CI e GitHub Code Scanning
tbm secrets .                        # sai com código 1 se achar algo
tbm secrets . -o segredos.sarif      # anotações nos PRs do GitHub

# Histórico, diff e relatórios
tbm history
tbm diff <scan_id_antigo> <scan_id_novo>
tbm report <scan_id> -o relatorio.html   # ou .json / .sarif

# Privacidade e CI
tbm scan ... --no-evidence           # não grava banners nem trechos de evidência
tbm scan ... --fail-on high          # código de saída 1 se houver HIGH+

tbm checks                           # lista os checks registrados
```

Variáveis de ambiente:

- `NVD_API_KEY`: chave gratuita do NVD; sobe o limite de 5 para 50 requisições a cada 30s ([pedir aqui](https://nvd.nist.gov/developers/request-an-api-key)).
- `TBM_WEBHOOK`: webhook padrão para alertas.
- `TBM_HOME`: onde ficam o histórico, os caches e a base OUI (padrão: `~/.threeblindmice`, com permissão 700 no Linux/macOS).

### Falsos positivos de segredos

- Na linha: adicione um comentário com `tbm:allow`.
- Por caminho: liste no `.tbmignore` (`tests/`, `*.lock`, `docs/**`).

### Pre-commit

```bash
pip install pre-commit && pre-commit install
```

O [.pre-commit-config.yaml](.pre-commit-config.yaml) roda o ruff e o `tbm secrets` em cada commit. Outros repositórios podem usar o hook `tbm-secrets` deste projeto pelo [.pre-commit-hooks.yaml](.pre-commit-hooks.yaml).

### Docker

```bash
docker build -t tbm .
docker run --rm --network host -v tbm-data:/data tbm scan 192.168.0.0/24 --label casa
```

## Arquitetura

```
src/tbm/
├── models.py          # Host, Service, TLSInfo, Finding, ScanResult (pydantic)
├── scope.py           # allowlist, expansão de alvos, enforce() para dados de fora
├── paths.py           # TBM_HOME, diretórios privados
├── asyncutil.py       # gather_limited (pool de workers) e RateLimiter
├── pipeline.py        # Scout → Sniffer → nota → histórico (ScanJob/execute)
├── cli.py             # Typer + Rich
├── scout/
│   ├── portscan.py    # connect scan, TCP ping, DNS reverso
│   ├── banner.py      # sondas por porta + assinaturas regex
│   ├── tls.py         # certificado e TLS 1.0/1.1 (com status "não testável")
│   ├── udp.py         # sondas UDP por protocolo
│   ├── wire.py        # DNS (com compressão) e SNMP/BER feitos à mão
│   ├── arp.py         # tabela ARP do SO e base OUI do IEEE
│   └── engine.py
├── sniffer/
│   ├── base.py        # Check, CheckContext, @register
│   ├── service_checks.py, tls_checks.py, http_checks.py, udp_checks.py
│   ├── ssh_checks.py  # KEXINIT manual, Terrapin, auth via paramiko
│   ├── smb_checks.py  # NEGOTIATE SMB1/SMB2 montado com struct
│   ├── cve.py         # NVD 2.0 com cache e rate limit
│   ├── epss.py        # FIRST.org EPSS
│   ├── backport.py    # comparação de versões dpkg + tracker do Ubuntu
│   ├── secrets.py     # regex + entropia, .tbmignore, tbm:allow
│   └── engine.py
├── squeak/
│   ├── scoring.py     # nota exponencial ponderada por KEV/EPSS
│   ├── store.py       # SQLite com migração aditiva
│   ├── diff.py        # fingerprints, portas, dispositivos e MAC
│   ├── sarif.py       # SARIF 2.1.0 para o GitHub
│   ├── redact.py      # --no-evidence
│   ├── report.py + templates/report.html.j2
│   └── notify.py
└── dashboard/         # FastAPI + HTMX, gráficos SVG gerados no servidor
```

### Decisões de design que valem estudar

- **Connect scan em vez de SYN scan:** não precisa de admin nem do Npcap, e funciona igual em qualquer SO.
- **`gather_limited`:** recebe *fábricas* de corrotinas, não corrotinas. Assim só existem `limit` corrotinas vivas por vez, mesmo varrendo um /16 inteiro.
- **Escopo em duas camadas:** `Scope.resolve()` valida os alvos digitados, e o `Sniffer` chama `Scope.enforce()` de novo sobre os hosts antes de qualquer check. Um JSON adulterado não consegue apontar os checks ativos para fora do escopo. As conexões sempre usam o IP validado, nunca o hostname resolvido de novo (proteção contra DNS rebinding).
- **UDP por sonda de protocolo:** em UDP, silêncio não diz nada. Só um pacote válido do protocolo faz o serviço responder.
- **Prioridade real em vez de CVSS puro:** KEV > EPSS > CVSS. Um CVE 9.8 com EPSS de 0,2% pesa menos na nota do que um 6.5 explorado em massa.
- **Backport:** `OpenSSH_8.2p1 Ubuntu-4ubuntu0.9` não é o mesmo que `8.2p1`. Comparamos a revisão do pacote com a versão corrigida usando o algoritmo do dpkg (`~` vem antes de tudo, letras antes de símbolos).
- **Fingerprint estável dos achados:** `sha1(check_id|host|port|key)`. É o que permite ao diff dizer "este achado é o mesmo do mês passado", mesmo com `--no-evidence`.
- **Dashboard somente leitura:** nenhum endpoint dispara scan. Mesmo exposto por engano, ele não vira um scanner controlável pela rede.

### Escrevendo um check novo

```python
# src/tbm/sniffer/meu_check.py
from tbm.models import Finding, Severity
from tbm.sniffer.base import Check, CheckContext, register

@register
class MeuCheck(Check):
    id = "service.exemplo"
    name = "Meu check"
    active_only = False

    async def run(self, ctx: CheckContext) -> list[Finding]:
        out = []
        for host, svc in ctx.services(lambda s: s.port == 8080):   # transport="udp" para UDP
            out.append(Finding(check_id=self.id, title="...", severity=Severity.LOW,
                               host=host.address, port=svc.port))
        return out
```

Depois, importe o módulo em `sniffer/engine.py` para registrar.

## Testes

```bash
pytest -q                     # unitários: sem rede externa, rodam em segundos
```

Os testes sobem servidores falsos em `127.0.0.1` (SSH, FTP, DNS), simulam NVD, EPSS e Ubuntu com o `httpx.MockTransport` e geram certificados na hora.

Integração com serviços reais (Redis sem senha, vsftpd anônimo, nginx com `.git`, OpenSSH com CBC, SNMP `public`), numa rede Docker isolada sem acesso à internet:

```bash
docker compose -f integration/compose.yml up --build --abort-on-container-exit --exit-code-from scanner
```

O CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) roda lint, testes em Linux/Windows/macOS × Python 3.11–3.13, a integração e o `tbm secrets` com upload do SARIF.

## Limitações conhecidas

- Backport: o tracker do Ubuntu é consultado automaticamente. Para o Debian, o achado só indica onde confirmar.
- O MAC só é obtido para hosts no mesmo segmento de rede (L2).
- Achados de rede no SARIF não aparecem na aba Security do GitHub, porque ela exige arquivo e linha. Só os segredos aparecem.
- O dashboard carrega o HTMX do unpkg; sem internet, a página inicial abre, mas os painéis não carregam.
