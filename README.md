# 🐭🐭🐭 threeblindmice

Toolkit **defensivo** de avaliação de segurança para redes e serviços que você controla.
São três "mice" que trabalham em sequência:

| Mouse | Papel | O que faz |
|---|---|---|
| **Scout** | Reconhecimento | Descobre dispositivos por TCP, ping ICMP, tabela ARP e mDNS/SSDP por multicast. Varre portas TCP e UDP, faz fingerprint de serviços, coleta certificados TLS e identifica cada aparelho: MAC, fabricante, nome anunciado e tipo (roteador, celular, TV, impressora…) |
| **Sniffer** | Análise | Tem 15 checks plugáveis: serviços de risco, Redis sem senha, SMBv1 e signing, SSH (algoritmos, Terrapin, auth), TLS, HTTP, UDP, **portas que o roteador abriu via UPnP**, AJP confirmado por protocolo, CVEs priorizados por **CISA KEV + EPSS** com filtro de backport e segredos em código. A severidade é calibrada pelo contexto (LAN × internet) |
| **Squeak** | Comunicação | Dá uma nota de 0 a 100 (A a F), guarda o histórico em SQLite e compara scans **por dispositivo, não por IP**. Permite aceitar riscos com prazo, gera relatório HTML/JSON/SARIF, envia alertas (Discord, Slack, Telegram, ntfy, webhook), escreve a carta para o provedor e tem um dashboard que funciona offline |

> ⚠️ Use somente em sistemas que são seus ou que você tem autorização por escrito para testar.
> Por padrão, o tbm **recusa** qualquer alvo fora das redes privadas.

## Instalação

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows  (Linux/macOS: source .venv/bin/activate)
pip install -e ".[dev]"          # ou ".[web]" só para o dashboard, ou "." para o básico
tbm update-oui                   # opcional: base de fabricantes de placas de rede (IEEE, ~3 MB)
```

## Interface gráfica

```bash
tbm gui
```

Abre o navegador numa interface local onde você pode:
- **fazer um scan** com a sua rede já preenchida, as opções explicadas e o progresso ao vivo;
- ver os **achados** com filtros, explicação e como corrigir, e **aceitar riscos** com um clique;
- consultar os **dispositivos** e a evolução da nota;
- conhecer **todas as funcionalidades**, com o comando equivalente de cada uma.

A interface escuta só em `127.0.0.1` e exige o token de sessão que vem no link aberto pelo comando. As ações têm proteção contra CSRF e DNS rebinding (veja [security.py](src/tbm/dashboard/security.py)). O `tbm dashboard` continua existindo, somente leitura.

## Uso pela linha de comando

```bash
# Os três juntos: rede de casa, com UDP e rótulo para o histórico
tbm scan 192.168.0.0/24 --label casa --udp

# Rede com câmeras/lâmpadas frágeis: 16 sockets e 50 conexões/s
tbm scan 192.168.0.0/24 --label casa --gentle

# Mais fundo: checks ativos e todas as portas, num host só
tbm scan 192.168.0.10 -p all --active --label nas

# Seu VPS (IP público): exige scope.yaml com authorized: true
copy scope.example.yaml scope.yaml
tbm scan 203.0.113.10 --scope scope.yaml --label vps --active
```

### Riscos que você não pode corrigir

```bash
tbm accept fb247b80 -l casa -r "ONT da operadora; chamado aberto" --until 2027-03-01
tbm accepted                       # lista (ativos e expirados)
tbm unaccept fb247b80
```

O `id` aparece na última coluna da tabela de achados. O achado continua no relatório, mas sai da nota e dos alertas. Quando a data vence, ele volta a contar.

### Carta para o provedor

```bash
tbm letter 192.168.100.175 -l casa --name "Seu Nome" -o chamado.txt
```

Gera um texto pronto com os achados do equipamento, as evidências e pedidos concretos (desativar Telnet, atualizar firmware…).

### Vigia contínuo

```bash
# Registra no Agendador de Tarefas (Windows), systemd --user (Linux) ou mostra a linha do cron
tbm schedule install 192.168.0.0/24 -l casa --every 6h --notify ntfy://minha-casa-tbm --dry-run
tbm schedule install 192.168.0.0/24 -l casa --every 6h --notify ntfy://minha-casa-tbm
tbm schedule remove -l casa

# Ou em primeiro plano, neste terminal
tbm watch 192.168.0.0/24 --label casa --every 6h --notify ...
```

Destinos de `--notify` (ou `TBM_WEBHOOK`):

| Destino | Formato |
|---|---|
| ntfy (push grátis no celular) | `ntfy://<tópico>` ou `https://ntfy.sh/<tópico>` |
| Telegram | `tg://<token-do-bot>/<chat_id>` |
| Discord / Slack | URL do webhook |
| Qualquer outro | URL https (recebe um POST com JSON completo) |

### Outros comandos

```bash
tbm dashboard                        # http://127.0.0.1:8765, somente leitura, funciona offline
tbm scout 192.168.0.0/24 -o scout.json && tbm sniff scout.json --active   # em etapas
tbm secrets . -o segredos.sarif      # credenciais vazadas → anotações nos PRs do GitHub
tbm history / tbm diff <a> <b> / tbm report <scan_id> -o r.html
tbm checks                           # lista os checks
```

Variáveis de ambiente: `NVD_API_KEY` (limite do NVD sobe de 5 para 50 req/30s), `TBM_WEBHOOK`, `TBM_HOME` (padrão `~/.threeblindmice`).

Falsos positivos de segredos: use um comentário `tbm:allow` na linha ou liste o caminho no `.tbmignore`.

## Arquitetura

```
src/tbm/
├── models.py          # Host (com identity), Service, Finding (com device, accepted), ScanResult
├── scope.py           # allowlist, expansão de alvos, enforce(), is_public()
├── pipeline.py        # Scout → Sniffer → aceitações → nota → histórico
├── schedule.py        # schtasks / systemd --user / cron
├── cli.py             # Typer + Rich
├── scout/
│   ├── discovery.py   # ping do SO, gateway padrão, mDNS/SSDP multicast
│   ├── classify.py    # tipo de dispositivo por pontuação de evidências
│   ├── portscan.py    # connect scan, TCP ping, rate limit (--gentle)
│   ├── banner.py, tls.py, udp.py, arp.py
│   └── wire.py        # DNS/mDNS e SNMP/BER feitos à mão, blindados contra pacotes malformados
├── sniffer/
│   ├── context.py     # severidade LAN × internet, numa tabela só
│   ├── upnp_checks.py # SSDP → XML → SOAP: redirecionamentos de porta do roteador
│   ├── service_checks.py, ssh_checks.py, smb_checks.py, tls_checks.py, http_checks.py, udp_checks.py
│   ├── cve.py, epss.py, backport.py, secrets.py
│   └── engine.py      # roda os checks, une CVEs duplicados, aplica o contexto
├── squeak/
│   ├── diff.py        # por identidade de dispositivo, com migração de fingerprints antigos
│   ├── acceptance.py  # riscos aceitos com prazo
│   ├── letter.py      # carta para o provedor
│   ├── notify.py      # Discord, Slack, Telegram, ntfy, webhook
│   ├── scoring.py, store.py, sarif.py, redact.py, report.py
└── dashboard/         # FastAPI + loader JS próprio (sem CDN), inventário de dispositivos
```

### Decisões de design que valem estudar

- **Descoberta em camadas:** só o TCP achou 3 de 254 IPs na rede de teste. Celulares e IoT costumam não ter porta comum aberta. Ping do SO (que já tem permissão para ICMP), tabela ARP e multicast mDNS/SSDP cobrem os outros, sem exigir admin.
- **Identidade ≠ IP:** o diff e os fingerprints usam o MAC (até o "aleatório" dos celulares é fixo por rede Wi-Fi). Assim, o DHCP trocar o IP de um aparelho não gera alerta falso. Scans antigos são comparados pela chave legada uma única vez, para o upgrade não disparar uma enxurrada de "novos".
- **Confirmar o protocolo antes de acusar:** a porta 8009 era tratada como "Tomcat AJP", mas em casa ela é Google Cast. Agora o tbm manda um CPing AJP e só acusa se vier o CPong.
- **Contexto central:** a mesma porta tem riscos diferentes na LAN e na internet (SMB: médio × crítico). Uma tabela em `context.py` substitui `if`s espalhados.
- **Parsers sob fuzzing:** tudo que interpreta bytes de aparelhos alheios só pode levantar o erro documentado. O `hypothesis` testa milhares de entradas malformadas a cada execução.
- **UPnP sem SSRF:** o LOCATION e o controlURL vêm do roteador; só seguimos URLs para o mesmo IP já validado pelo escopo.
- **Escopo em duas camadas, prioridade KEV > EPSS > CVSS, backport via dpkg, dashboard somente leitura:** detalhes nos docstrings de cada módulo.

## Testes e CI

```bash
pytest -q                     # unitários + fuzzing, sem rede externa
mypy src                      # tipos
docker compose -f integration/compose.yml up -d --build --wait redis ftp web ssh snmp
docker compose -f integration/compose.yml run --rm --build scanner
docker compose -f integration/compose.yml down -v
```

O CI ([ci.yml](.github/workflows/ci.yml)) roda ruff, mypy, testes em Linux/Windows/macOS × Python 3.11–3.13, o laboratório de integração e o `tbm secrets` com SARIF.

Releases ([release.yml](.github/workflows/release.yml)): uma tag `vX.Y.Z` roda o CI e publica no PyPI (trusted publishing, configurado uma vez em pypi.org), a imagem em `ghcr.io/<dono>/threeblindmice` e o GitHub Release.

## Limitações conhecidas

- Backport: o tracker do Ubuntu é consultado automaticamente. Para o Debian, o achado só indica onde confirmar.
- MAC e tabela ARP: só para hosts no mesmo segmento de rede (L2). Entradas antigas da tabela ARP podem listar um aparelho que já saiu da rede.
- Achados de rede no SARIF não aparecem na aba Security do GitHub, porque ela exige arquivo e linha. Só os segredos aparecem.
- A classificação de dispositivo é heurística e pode errar ou ficar em branco. Rodar o `tbm update-oui` ajuda bastante.
