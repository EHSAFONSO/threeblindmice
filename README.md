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

### Windows: instalador

Baixe o `threeblindmice_<versão>_x64-setup.exe` na [página de releases](https://github.com/EHSAFONSO/threeblindmice/releases/latest) e execute. Não precisa de Python nem de permissão de administrador. O instalador cria o atalho no menu Iniciar (e, se você quiser, na Área de Trabalho) e pode adicionar o comando `tbm` ao terminal. Ele aparece em "Aplicativos instalados", de onde dá para desinstalar. A desinstalação remove os vigias criados pelo app, mas mantém o seu histórico em `~/.threeblindmice`.

O instalador ainda não tem assinatura digital, então o Windows pode mostrar "O Windows protegeu o computador": clique em *Mais informações* e depois em *Executar assim mesmo*. Antes, confira que o arquivo é o original comparando o SHA-256 com o do arquivo `.sha256` publicado na release:

```bash
certutil -hashfile threeblindmice_0.9.0_x64-setup.exe SHA256
```

Para gerar o instalador você mesmo: `pip install -e ".[desktop]" pyinstaller` e `python packaging/windows/build.py` (precisa do [Inno Setup 6](https://jrsoftware.org/isinfo.php)).

### Pelo Python (Windows, Linux e macOS)

Para usar, basta `pip install "threeblindmice[desktop]"`, ou `[web]` só para a interface no navegador. Se quiser a mesma proteção de cadeia de suprimentos do projeto, só wheels e versões com 3 dias ou mais, use `pip install --only-binary :all: --no-binary proxy-tools --uploaded-prior-to P3D "threeblindmice[desktop]"`.

Para desenvolver, com as versões exatas do lock (veja [Cadeia de suprimentos](#cadeia-de-suprimentos)):

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows  (Linux/macOS: source .venv/bin/activate)
copy requirements\pip.conf .venv\pip.ini     # Linux/macOS: cp requirements/pip.conf .venv/pip.conf
python -m pip install --require-hashes --only-binary :all: --no-deps -r requirements/bootstrap.txt
python -m pip install --require-hashes --no-build-isolation -r requirements/desktop.txt
python -m pip install --no-deps --no-build-isolation -e .
tbm update-oui                   # opcional: base de fabricantes de placas de rede (IEEE, ~3 MB)
```

## Interface gráfica

```bash
tbm gui
```

Abre o navegador numa interface local onde você pode:
- ver a **saúde da rede** de relance: nota no medidor, variação desde o último scan, progresso e as **3 ações mais importantes agora**, com quantos pontos cada uma soma e a nota que você terá ao fazer as três ("D → B");
- **corrigir agora**: cada ação vira um passo a passo marcável e termina num botão "Já fiz, verificar", que escaneia só aquele aparelho em segundos e mostra o que foi resolvido;
- fazer um scan **ao vivo**, com as etapas e os aparelhos aparecendo conforme são encontrados (a primeira abertura traz um assistente de boas-vindas);
- ver os **achados agrupados pela correção** ("atualizar o firmware do modem resolve 4 achados"), priorizados por KEV/EPSS, e **aceitar riscos** com um clique;
- explorar o **mapa da rede** (internet → roteador → aparelhos, colorido pelo pior problema, com aviso de NAT duplo) e os **dispositivos**, cada um com painel de detalhes;
- acompanhar a **linha do tempo** da nota, com os scans que trouxeram mudanças marcados;
- dar **nome** aos aparelhos e **aprovar** os que são seus: aparelho desconhecido na rede chega como alerta destacado;
- seguir o **passo a passo da correção no seu roteador**: a marca (ZTE, Huawei, Nokia, TP-Link, Intelbras, Fiberhome, Tenda, D-Link, Mercusys) é deduzida do que o próprio aparelho revela;
- configurar **alertas** (assistente do Telegram, ntfy, Discord/Slack), com mensagem de teste antes de salvar;
- ligar o **vigia automático**, que roda sem abrir janela e mostra a próxima execução e a saída das últimas;
- gerar a **carta para o provedor** de qualquer equipamento com achados;
- conhecer **todas as funcionalidades**, com o comando equivalente de cada uma.

A navegação fica numa barra lateral recolhível, com **busca global** (`Ctrl+K` ou `/`: aparelhos, ações e páginas), **notificações** (aparelho desconhecido, scan concluído, problemas resolvidos) e atalhos (`N` novo scan, `G` e depois `M` para o mapa). O **modo simples** esconde portas, CVEs e evidências para quem só quer saber o que fazer. Cada aparelho tem página própria, com histórico de IPs, portas e problemas, categoria e notas; o mapa tem zoom, filtros e mostra quem saiu da rede. Renomear, aprovar e aceitar riscos acontece sem recarregar a página, com "Desfazer".

Tem tema claro, escuro ou automático, em **português ou inglês** (botão PT/EN, ou o idioma do navegador), funciona só com teclado e não carrega nada de fora (CSS, JS e ícones são locais). O relatório HTML (o "Relatório completo" da interface, ou o `.html` gerado pelo `tbm run`) traz as ações por prioridade e sai bem impresso ou em PDF.

O destino dos alertas fica em `~/.threeblindmice/config.json`, legível só pelo seu usuário. A ordem de prioridade é `--notify`, depois a variável `TBM_WEBHOOK`, depois o arquivo.

A interface escuta só em `127.0.0.1` e exige o token de sessão que vem no link aberto pelo comando. As ações têm proteção contra CSRF e DNS rebinding (veja [security.py](src/tbm/dashboard/security.py)). O `tbm dashboard` continua existindo, somente leitura.

### Aplicativo de desktop

```bash
pip install "threeblindmice[desktop]"
tbm app                       # a mesma interface, numa janela própria
tbm shortcut install          # atalho no menu Iniciar (Windows) ou no lançador (Linux)
tbm shortcut install --desktop  # também na Área de Trabalho
```

No Windows e no Linux, o app fica com um **ícone na bandeja**, com um ponto colorido pela nota do último scan (verde a vermelho). Fechar a janela só a esconde: scans em andamento continuam, e uma notificação avisa quando terminam. Para encerrar, use "Sair" no menu da bandeja (ou `tbm app --no-tray` para fechar junto com a janela). Abrir o app de novo traz para a frente a janela que já está aberta; se a versão instalada mudou, a instância antiga é encerrada e a nova assume. A bandeja mostra a nota, os aparelhos não aprovados e tem "Escanear agora", e a barra de título da janela segue as cores do app.

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
| E-mail (SMTP) | `smtp://usuario:senha@servidor:587/destino@exemplo.com` |
| Pushover | `pushover://<app_token>@<user_key>` |
| Home Assistant | `hass://seu-ha:8123/<webhook_id>` |
| Qualquer outro | URL https (recebe um POST com JSON completo) |

Dá para definir um **horário de silêncio** (só alertas críticos passam de madrugada) e o resumo semanal avisa quando uma **aceitação de risco está para vencer**.

### O que mais o scan olha

Além dos aparelhos, o scan da rede local verifica:

- **Wi-Fi**: a criptografia da rede em que o computador está (aberta, WEP, WPA/TKIP, WPA2, WPA3);
- **IPv6**: aparelhos com endereço IPv6 público e portas que também respondem por ele. No IPv6 não há NAT, então só o firewall do roteador protege;
- **nomes**: quando o DNS não sabe o nome do aparelho, o tbm pergunta direto a ele, via NetBIOS e LLMNR;
- **modelo e firmware**: lê o que o próprio aparelho anuncia (UPnP, SNMP), para os guias e a busca de CVEs ficarem exatos;
- **Wi-Fi falso**: avisa se existe uma rede aberta com o mesmo nome da sua (golpe do "gêmeo maligno");
- **DHCP intruso**: avisa se há mais de um servidor DHCP respondendo (sinal de interceptação);
- **casa conectada**: câmera entregando vídeo sem senha (RTSP), broker MQTT anônimo, impressoras e gravadores expostos;
- **senha de fábrica**: lembra de conferir a senha de roteadores e câmeras — o tbm **não tenta adivinhar senha nenhuma**;
- **NAT duplo e CGNAT**: confirmados pelo IP externo que o roteador informa.

Com `--external` (na interface, "Verificações externas") entram mais dois testes, que mandam o seu IP público para serviços de terceiros:

- **o que a internet vê**: as portas do seu IP público, segundo o Shodan InternetDB;
- **DNS sequestrado**: compara as respostas do DNS do roteador com o DNS da Cloudflare (DoH), e acusa sinais de roteador invadido.

### Resumo semanal e novas versões

Com um destino de alertas configurado, o vigia manda uma vez por semana um **resumo**: a nota, o que mudou e a próxima ação, mesmo sem novidade. Assim você sabe que ele continua rodando. Para controlar:

```bash
tbm summary --label casa --send      # manda agora
tbm summary --disable                # desliga o automático
```

A interface avisa quando há **versão nova** no GitHub (uma consulta por dia). O tbm só avisa: não baixa nem instala nada sozinho. Junto com o aviso vêm o SHA-256 publicado e o comando para verificar o atestado. Para desligar: `tbm update --disable`.

### Vigia em tempo real, perfis de rede e mais

- **Vigia em tempo real**: com o app aberto (mesmo só na bandeja), uma thread leve relê a rede a cada minuto e avisa na hora quando um aparelho novo aparece, sem esperar o scan agendado. Em "Vigia" dá para ligar **iniciar com o sistema** (desligado por padrão).
- **Perfis de rede**: o app reconhece em que rede você está pelo MAC do roteador e sugere o histórico certo ("casa", "escritório"). Se o computador está em mais de uma rede (cabo, Wi-Fi, convidados, VM), o formulário de scan oferece todas.
- **Comparar scans** e **relatório para a família**: na linha do tempo, veja dois momentos lado a lado, ou gere uma página simples (sem jargão) para imprimir ou salvar em PDF.
- **Modo demonstração**: `tbm demo` abre a interface com uma rede fictícia, sem tocar no seu histórico (bom para prints e apresentações).
- **Métricas**: `tbm dashboard` expõe `GET /metrics` no formato Prometheus (só a nota e as contagens agregadas, nunca IPs ou nomes).

### Instalar

O instalador do Windows, o `pip` e o Docker continuam valendo (veja [Instalação](#instalação)). A imagem Docker agora é **multiarquitetura** (x86-64 e ARM64), então roda num Raspberry Pi ou NAS para deixar o vigia 24 h. Há também um manifesto do **Scoop** em `packaging/scoop/`.

### Outros comandos

```bash
tbm dashboard                        # http://127.0.0.1:8765, somente leitura, funciona offline
tbm scout 192.168.0.0/24 -o scout.json && tbm sniff scout.json --active   # em etapas
tbm secrets . -o segredos.sarif      # credenciais vazadas → anotações nos PRs do GitHub
tbm history / tbm diff <a> <b> / tbm report <scan_id> -o r.html
tbm history prune --dry-run          # limpa scans antigos: tudo de 30 dias, 1/semana até 1 ano, 1/mês depois
tbm checks                           # lista os checks
tbm scan 10.0.0.0/16 --resume        # rede grande: continua um scan interrompido (checkpoint por bloco /24)
```

Em redes acima de /22, a descoberta fica rápida sozinha (`--discovery auto`). O TCP passa a testar 4 portas em vez de 12, sem um ping do sistema por IP. Depois, o ping vai só para os blocos /24 roteados em que algo respondeu, com um teto de 4.096 endereços. O timeout segue o RTT medido. O paralelismo cai pela metade se o sistema começar a recusar sockets. Na interface, o scan em andamento mostra o tempo restante e tem um botão **Cancelar**. O relatório mostra o tempo gasto em cada fase.

Variáveis de ambiente: `NVD_API_KEY` (limite do NVD sobe de 5 para 50 req/30s), `TBM_WEBHOOK`, `TBM_HOME` (padrão `~/.threeblindmice`).

Falsos positivos de segredos: use um comentário `tbm:allow` na linha ou liste o caminho no `.tbmignore`.

### Plugins

Terceiros podem acrescentar **checks**, **destinos de alerta** e **enriquecedores de descoberta** em pacotes Python próprios, usando a API estável `tbm.plugin`. Um plugin roda código com acesso à sua rede, então **nada é carregado só por estar instalado**: cada pacote precisa ser autorizado.

```bash
tbm plugins list                         # instalados e autorizados
tbm plugins enable tbm-plugin-exemplo    # mostra o que o pacote registra e pede confirmação
tbm plugins disable tbm-plugin-exemplo
```

Os checks de plugins aparecem em `tbm checks` e na página Funcionalidades com a origem (pacote e versão). Um plugin com erro fica de fora e é anotado, sem derrubar o scan. `TBM_NO_PLUGINS=1` desliga todos. Para criar um, veja [`examples/tbm-plugin-exemplo`](examples/tbm-plugin-exemplo/src/tbm_plugin_exemplo/__init__.py).

## Arquitetura

```
src/tbm/
├── models.py          # Host (com identity), Service, Finding (com device, accepted), ScanResult
├── scope.py           # allowlist, expansão de alvos, enforce(), is_public()
├── pipeline.py        # Scout → Sniffer → aceitações → nota → histórico
├── schedule.py        # schtasks / systemd --user / cron
├── plugin.py          # API pública e estável para plugins; plugins.py carrega os autorizados
├── cli/               # Typer + Rich: um módulo por área (scan, watch, history, alerts, ui, plugins, tools)
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
│   ├── notifiers.py   # registro de destinos: Telegram, ntfy, Pushover, Home Assistant, e-mail, Discord, Slack, webhook
│   ├── store.py       # SQLite (WAL) com migrações versionadas, índices por aparelho/achado e blobs comprimidos
│   ├── notify.py, scoring.py, sarif.py, redact.py, report.py
└── dashboard/         # FastAPI: routes/ (um router por área), templating.py, loader JS próprio (sem CDN)
```

### Decisões de design que valem estudar

- **Descoberta em camadas:** só o TCP achou 3 de 254 IPs na rede de teste. Celulares e IoT costumam não ter porta comum aberta. Ping do SO (que já tem permissão para ICMP), tabela ARP e multicast mDNS/SSDP cobrem os outros, sem exigir admin.
- **Identidade ≠ IP:** o diff e os fingerprints usam o MAC (até o "aleatório" dos celulares é fixo por rede Wi-Fi). Assim, o DHCP trocar o IP de um aparelho não gera alerta falso. Scans antigos são comparados pela chave legada uma única vez, para o upgrade não disparar uma enxurrada de "novos".
- **Confirmar o protocolo antes de acusar:** a porta 8009 era tratada como "Tomcat AJP", mas em casa ela é Google Cast. Agora o tbm manda um CPing AJP e só acusa se vier o CPong.
- **Contexto central:** a mesma porta tem riscos diferentes na LAN e na internet (SMB: médio × crítico). Uma tabela em `context.py` substitui `if`s espalhados.
- **Parsers sob fuzzing:** tudo que interpreta bytes de aparelhos alheios só pode levantar o erro documentado. O `hypothesis` testa milhares de entradas malformadas a cada execução.
- **UPnP sem SSRF:** o LOCATION e o controlURL vêm do roteador; só seguimos URLs para o mesmo IP já validado pelo escopo.
- **Escopo em duas camadas, prioridade KEV > EPSS > CVSS, backport via dpkg, dashboard somente leitura:** detalhes nos docstrings de cada módulo.

## Cadeia de suprimentos

Um pacote sequestrado no PyPI rodaria com as permissões do CI, de quem publica no PyPI ou de quem instala o setup.exe. Por isso, nada entra sem estar travado:

| Camada | Como |
|---|---|
| Versões exatas | `requirements/*.txt` (o "package-lock" do projeto), gerados pelo `uv` para Windows, Linux e macOS de uma vez, com o SHA-256 de cada arquivo. Um arquivo trocado no PyPI não instala. |
| Sem scripts de instalação | Só wheels (`only-binary = :all:`): instalar não executa `setup.py`. O build não baixa ferramentas soltas (`--no-build-isolation`, com hatchling e setuptools travados). A única exceção é o `proxy-tools` (dependência do pywebview, sem wheel no PyPI): são 178 linhas revisadas, travadas pelo hash. |
| Idade mínima de 3 dias | `uploaded-prior-to = P3D` no pip e `exclude-newer = "3 days"` no uv: versões recém-publicadas, que é quando um sequestro costuma ser descoberto e removido, ficam de fora. |
| GitHub Actions | Fixadas pelo SHA do commit, não pela tag (uma tag pode ser movida para código malicioso). |
| Imagens Docker | Fixadas por digest (`python:3.12-slim@sha256:…`), inclusive as do laboratório de integração. |
| Origem comprovada | Cada release traz atestados de origem (SLSA, assinados pelo Sigstore) do wheel, do sdist, do setup.exe e da imagem Docker, e listas de componentes (SBOM CycloneDX). Para conferir: `gh attestation verify <arquivo> --repo EHSAFONSO/threeblindmice`. |
| Vulnerabilidades | O `pip-audit` roda no CI contra os três locks. |
| Atualização com quarentena | O Dependabot propõe Actions e imagens novas com espera (cooldown) de 3 dias. Toda segunda, o [lock-refresh.yml](.github/workflows/lock-refresh.yml) regenera os locks com o `uv` e o `pip-audit` e publica um branch para revisão. |
| Uma porta de entrada | O CI instala tudo pela action [.github/actions/install](.github/actions/install/action.yml). O [test_supply_chain.py](tests/test_supply_chain.py) falha se aparecer um `pip install` solto, uma Action sem SHA, uma imagem sem digest ou um pacote sem hash. |

A política do pip fica em [requirements/pip.conf](requirements/pip.conf). O CI e o Docker a usam via `PIP_CONFIG_FILE`; no seu venv, copie para `.venv/pip.ini` (Windows) ou `.venv/pip.conf`.

Para atualizar as dependências, rode `python requirements/lock.py --upgrade` (precisa do `uv`). Ele só escolhe versões com 3 dias ou mais. Depois confira o diff dos locks e rode `pip-audit -r requirements/desktop.txt --no-deps --disable-pip` para checar vulnerabilidades conhecidas.

As faixas (`>=`) do `pyproject.toml` continuam, de propósito: quem instala o tbm do PyPI como biblioteca precisa de flexibilidade. O travamento vale para o que o projeto constrói e distribui: o CI, a imagem Docker, o pacote do PyPI e o setup.exe.

## Testes e CI

```bash
pytest -q                     # unitários, fuzzing e interface no navegador, sem rede externa
pytest -m e2e                 # só a interface no navegador (Playwright + Edge/Chrome já instalados)
mypy src                      # tipos
docker compose -f integration/compose.yml up -d --build --wait redis ftp web ssh snmp
docker compose -f integration/compose.yml run --rm --build scanner
docker compose -f integration/compose.yml down -v
```

O CI ([ci.yml](.github/workflows/ci.yml)) roda ruff, mypy, testes em Linux/Windows/macOS × Python 3.11–3.13, a interface num navegador de verdade (Chrome e Edge), o `pip-audit`, o laboratório de integração e o `tbm secrets` com SARIF.

Releases ([release.yml](.github/workflows/release.yml)): uma tag `vX.Y.Z` roda o CI e publica no PyPI (trusted publishing, configurado uma vez em pypi.org), a imagem em `ghcr.io/<dono>/threeblindmice` e o GitHub Release, todos com atestados e SBOM.

**Assinatura do setup.exe:** o [SignPath](https://signpath.org) assina de graça projetos de código aberto. Depois de aprovado lá, crie no repositório as variáveis `SIGNPATH_ORGANIZATION_ID`, `SIGNPATH_PROJECT_SLUG` e `SIGNPATH_POLICY_SLUG` e o segredo `SIGNPATH_API_TOKEN`. O release passa a assinar o instalador sozinho, e o aviso do SmartScreen some.

## Limitações conhecidas

- Backport: o tracker do Ubuntu é consultado automaticamente. Para o Debian, o achado só indica onde confirmar.
- MAC e tabela ARP: só para hosts no mesmo segmento de rede (L2). Entradas antigas da tabela ARP podem listar um aparelho que já saiu da rede.
- Achados de rede no SARIF não aparecem na aba Security do GitHub, porque ela exige arquivo e linha. Só os segredos aparecem.
- A classificação de dispositivo é heurística e pode errar ou ficar em branco. Rodar o `tbm update-oui` ajuda bastante.
