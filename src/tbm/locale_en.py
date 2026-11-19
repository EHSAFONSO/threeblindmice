"""English translations of the interface (the source text is Portuguese).

Keys are the exact Portuguese strings marked with `_()`; `{placeholders}` must
be kept. tests/test_i18n.py fails when a marked string has no entry here.
"""

EN: dict[str, str] = {
    # ── shell and navigation ──
    "Pular para o conteúdo": "Skip to content",
    "threeblindmice, página inicial": "threeblindmice, home page",
    "Interface local": "Local interface",
    "Dashboard somente leitura": "Read-only dashboard",
    "Principal": "Main",
    "Novo scan": "New scan",
    "Visão geral": "Overview",
    "Achados": "Findings",
    "Mapa": "Map",
    "Dispositivos": "Devices",
    "Alertas": "Alerts",
    "Vigia": "Watch",
    "Funcionalidades": "Features",
    "Alternar tema: automático, claro ou escuro": "Toggle theme: auto, light or dark",
    "Alternar tema (automático → claro → escuro)": "Toggle theme (auto → light → dark)",
    "Carregando…": "Loading…",
    "Cancelar": "Cancel",
    "Confirmar": "Confirm",
    "Salvar": "Save",
    "Falha ao carregar.": "Failed to load.",
    "Erro": "Error",
    "Fechar": "Close",

    # ── home / health ──
    "Nenhum scan no histórico ainda": "No scans in the history yet",
    "Rode": "Run",
    "ou abra a interface com": "or open the interface with",
    "Nota {g}, {s} de 100": "Grade {g}, {s} out of 100",
    "Saúde da rede": "Network health",
    "Sua rede está em boa forma.": "Your network is in good shape.",
    "Há pontos de atenção, mas nada grave.": "There are a few things to look at, but nothing serious.",
    "Há problemas que merecem atenção. Comece pelas ações abaixo.":
        "There are problems that need attention. Start with the actions below.",
    "{d} desde o scan anterior": "{d} since the previous scan",
    "nenhum achado aberto": "no open findings",
    "Situação": "Status",
    "Último scan {age}": "Last scan {age}",
    "relatório": "report",
    "{n} dispositivo(s)": "{n} device(s)",
    "ver no mapa": "see on the map",
    "Carregando vigia e alertas…": "Loading watch and alerts…",
    "Progresso das correções": "Fix progress",
    "{a} de {b}": "{a} of {b}",
    "resolvidos": "resolved",
    "{n} risco(s) aceito(s) fora da conta.": "{n} accepted risk(s) left out of the count.",
    "O que fazer agora": "What to do now",
    "resolve {n} achado(s)": "fixes {n} finding(s)",
    "explorada ativamente": "actively exploited",
    "explorada ativamente (CISA KEV)": "actively exploited (CISA KEV)",
    "Carta para o provedor": "Letter to the ISP",
    "Detalhes": "Details",
    "Ver todas as {n} ações →": "See all {n} actions →",
    "Nada a fazer agora. Os próximos scans avisam se algo mudar.":
        "Nothing to do right now. Upcoming scans will tell you if anything changes.",
    "Evolução": "History",
    "agora há pouco": "just now",
    "há {n} min": "{n} min ago",
    "há {n} h": "{n} h ago",
    "ontem": "yesterday",
    "há {n} dias": "{n} days ago",

    # ── status partial ──
    "Vigia ativo": "Watch on",
    "próximo às {t}": "next at {t}",
    "Vigia desligado": "Watch off",
    "ligar →": "turn on →",
    "Alertas:": "Alerts:",
    "Alertas desligados": "Alerts off",
    "configurar →": "set up →",

    # ── timeline ──
    "Linha do tempo": "Timeline",
    "pontos cheios = algo mudou · passe o mouse ou use Tab para detalhes":
        "filled dots = something changed · hover or use Tab for details",
    "Evolução da nota de {l}": "Grade history for {l}",
    "abrir relatório": "open report",
    "Scans": "Scans",
    "Quando": "When",
    "Nota": "Grade",
    "Abertos (crit/alto/méd/baixo)": "Open (crit/high/med/low)",
    "Ações": "Actions",
    "o que mudou?": "what changed?",
    "{n} dispositivo(s) novo(s)": "{n} new device(s)",
    "{n} achado(s) novo(s)": "{n} new finding(s)",
    "{n} resolvido(s)": "{n} resolved",
    "MAC trocado": "MAC changed",
    "{n} risco(s) aceito(s)": "{n} accepted risk(s)",
    "nota {g} {s}/100": "grade {g} {s}/100",

    # ── map ──
    "Mapa da rede": "Network map",
    "scan de {t} · clique num aparelho para ver os detalhes": "scan from {t} · click a device for details",
    "Mapa com {n} dispositivos": "Map with {n} devices",
    "roteador principal": "main router",
    "Contorno = pior problema aberto:": "Outline = worst open problem:",
    "crítico": "critical",
    "alto": "high",
    "médio": "medium",
    "baixo": "low",
    "sem problemas": "no problems",
    "Internet": "Internet",
    "O roteador principal foi estimado (scans anteriores à v0.7 não registravam o gateway).":
        "The main router was estimated (scans before v0.7 did not record the gateway).",
    "Há {n} roteadores/modems na mesma rede. Pode haver NAT duplo (comum quando o modem da operadora fica entre "
    "a internet e o seu roteador); vale conferir com o provedor.":
        "There are {n} routers/modems on the same network. You may have double NAT (common when the ISP's modem "
        "sits between the internet and your router); worth checking with your ISP.",

    # ── device drawer ──
    "tipo desconhecido": "unknown type",
    "Visto desde": "Seen since",
    "Encontrado por": "Found by",
    "Portas": "Ports",
    "nenhuma aberta": "none open",
    "Anuncia": "Announces",
    "O que fazer": "What to do",
    "Como fazer no seu {b}": "How to do it on your {b}",
    "Como fazer": "How to do it",
    "aceito": "accepted",
    "Nenhum achado neste aparelho.": "No findings on this device.",
    "Ver achados": "See findings",
    "Carta": "Letter",
    "Relatório do scan": "Scan report",

    # ── devices ──
    "Ver no mapa": "See on the map",
    "Último scan {id} em {t}": "Last scan {id} on {t}",
    "histórico de {n} scan(s).": "history of {n} scan(s).",
    "Cada aparelho é reconhecido pelo MAC (ou pelo nome anunciado), então trocar de IP não o transforma num "
    "aparelho novo.":
        "Each device is recognized by its MAC (or announced name), so getting a new IP does not make it a new device.",
    "abrir detalhes": "open details",
    "Sem nome": "No name",
    "detectado como {n}": "detected as {n}",
    "antes:": "before:",
    "{n} aceito(s)": "{n} accepted",
    "{n} porta(s)": "{n} port(s)",
    "visto {a}× de {b}": "seen {a}× out of {b}",
    "desde {d}": "since {d}",
    "Você aprovou este aparelho": "You approved this device",
    "conhecido": "known",
    "Remover aprovação": "Remove approval",
    "não aprovado": "not approved",
    "Aprovar": "Approve",
    "Renomear": "Rename",
    "carta para o provedor →": "letter to the ISP →",
    "Nome do aparelho": "Device name",
    "Como você chama este aparelho? Deixe vazio para voltar ao nome detectado.":
        "What do you call this device? Leave empty to go back to the detected name.",
    "Aparelho aprovado: não vai mais alertar como desconhecido": "Device approved: it will no longer alert as unknown",
    "Aprovação removida": "Approval removed",

    # ── findings ──
    "Aceitação:": "Acceptance:",
    "Risco aceito:": "Risk accepted:",
    "vale a partir do próximo scan.": "takes effect from the next scan.",
    "Evidência": "Evidence",
    "Como corrigir": "How to fix",
    "Desfazer aceitação": "Undo acceptance",
    "Aceitar risco…": "Accept risk…",
    "Motivo": "Reason",
    "Motivo (ex.: modem da operadora, chamado aberto)": "Reason (e.g. ISP's modem, ticket opened)",
    "válido até": "valid until",
    "Aceitar": "Accept",
    "O que corrigir": "What to fix",
    "Histórico": "History",
    "Último scan em {t}": "Last scan on {t}",
    "nota": "grade",
    "Os achados estão agrupados pela correção: uma ação costuma resolver vários de uma vez.":
        "Findings are grouped by fix: one action often resolves several at once.",
    "As primeiras são as que mais reduzem risco real (CISA KEV e EPSS).":
        "The first ones reduce real-world risk the most (CISA KEV and EPSS).",
    "Progresso": "Progress",
    "{a} de {b} problemas já resolvidos ({p}%)": "{a} of {b} problems already resolved ({p}%)",
    "Mostrar a partir de": "Show from",
    "Nada a corrigir neste scan.": "Nothing to fix in this scan.",
    "Riscos aceitos": "Accepted risks",
    "Informativos": "Informational",
    "Não são problemas: só registram o que foi observado.": "Not problems: they just record what was observed.",
    "{n} ação(ões) exibida(s)": "{n} action(s) shown",
    "Risco aceito. Sai da nota no próximo scan.": "Risk accepted. It leaves the grade on the next scan.",
    "Desfazer a aceitação?": "Undo the acceptance?",
    "O achado volta a contar na nota a partir do próximo scan.": "The finding counts toward the grade again from the next scan.",
    "Desfazer": "Undo",

    # ── fix kinds (actions) ──
    "Atualizar o firmware ou software de {dev}": "Update the firmware or software of {dev}",
    "Corrige vulnerabilidades conhecidas (CVEs) e algoritmos de criptografia fracos de uma vez.":
        "Fixes known vulnerabilities (CVEs) and weak encryption algorithms in one go.",
    "Desativar o Telnet em {dev}": "Turn off Telnet on {dev}",
    "O Telnet transmite senhas sem criptografia e dá acesso de terminal ao aparelho.":
        "Telnet sends passwords unencrypted and gives terminal access to the device.",
    "Desativar ou proteger o FTP em {dev}": "Turn off or protect FTP on {dev}",
    "O FTP envia usuário e senha em texto puro.": "FTP sends username and password in plain text.",
    "Restringir o acesso remoto (RDP/VNC) em {dev}": "Restrict remote access (RDP/VNC) on {dev}",
    "Acesso remoto exposto é alvo constante de força bruta.": "Exposed remote access is a constant brute-force target.",
    "Ajustar o compartilhamento de arquivos (SMB) de {dev}": "Fix file sharing (SMB) on {dev}",
    "SMB mal configurado é porta de entrada para ransomware.": "Misconfigured SMB is a doorway for ransomware.",
    "Proteger o banco de dados em {dev}": "Protect the database on {dev}",
    "Bancos acessíveis pela rede vazam ou perdem dados.": "Databases reachable over the network leak or lose data.",
    "Restringir a gerência remota (TR-069) de {dev}": "Restrict remote management (TR-069) on {dev}",
    "É a interface que o provedor usa para controlar o aparelho; já foi explorada em massa.":
        "It's the interface the ISP uses to control the device; it has been exploited at scale.",
    "Ativar HTTPS na administração de {dev}": "Enable HTTPS for the admin page of {dev}",
    "Senhas digitadas na página de administração trafegam sem criptografia.":
        "Passwords typed into the admin page travel unencrypted.",
    "Ajustar a configuração do servidor web de {dev}": "Fix the web server configuration on {dev}",
    "Headers de segurança, cookies e versão exposta: configurações básicas contra ataques web.":
        "Security headers, cookies and exposed version: basic settings against web attacks.",
    "Remover arquivos sensíveis do site em {dev}": "Remove sensitive files from the website on {dev}",
    "Arquivos como .git e .env expõem código e senhas.": "Files like .git and .env expose code and passwords.",
    "Fechar a API administrativa sem senha em {dev}": "Close the unauthenticated admin API on {dev}",
    "Quem acessa a API controla o serviço.": "Whoever reaches the API controls the service.",
    "Renovar ou ajustar o certificado TLS de {dev}": "Renew or fix the TLS certificate of {dev}",
    "Certificado ruim ensina a ignorar avisos de segurança.": "A bad certificate teaches people to ignore security warnings.",
    "Desativar o UPnP em {dev}": "Turn off UPnP on {dev}",
    "Com UPnP, qualquer programa da rede abre portas para a internet sem pedir permissão.":
        "With UPnP, any program on the network can open ports to the internet without asking.",
    "Desativar o SNMP ou trocar a senha padrão em {dev}": "Turn off SNMP or change the default password on {dev}",
    "Com a senha padrão 'public', qualquer um lê a configuração completa do aparelho.":
        "With the default 'public' password, anyone can read the device's full configuration.",
    "Remover a credencial de {dev}": "Remove the credential from {dev}",
    "Senhas em código acabam em backups e repositórios.": "Passwords in code end up in backups and repositories.",
    "Reforçar a segurança da {dev}": "Strengthen the security of the {dev}",
    "Criptografia fraca no Wi-Fi deixa vizinhos entrarem na rede e lerem o tráfego.":
        "Weak Wi-Fi encryption lets neighbors join the network and read the traffic.",
    "Conferir o firewall IPv6 de {dev}": "Check the IPv6 firewall of {dev}",
    "Sem NAT no IPv6, só o firewall do roteador separa os aparelhos da internet.":
        "With no NAT in IPv6, only the router's firewall separates devices from the internet.",
    "Corrigir o DNS de {dev}": "Fix the DNS of {dev}",
    "DNS adulterado manda você para sites falsos mesmo digitando o endereço certo.":
        "Tampered DNS sends you to fake sites even when you type the right address.",
    "Fechar o que a internet vê em {dev}": "Close what the internet sees on {dev}",
    "Portas visíveis da internet são varridas por robôs o tempo todo.": "Ports visible from the internet are scanned by bots all the time.",

    # ── new scan ──
    "O tbm descobre os aparelhos da rede, testa os serviços de cada um e dá uma nota de 0 a 100.":
        "tbm discovers the devices on the network, tests each one's services and gives a grade from 0 to 100.",
    "Só redes privadas são aceitas aqui. Para escanear um IP público (ex.: seu VPS), use a linha de comando com um":
        "Only private networks are accepted here. To scan a public IP (e.g. your VPS), use the command line with a",
    "O que escanear": "What to scan",
    "Detectamos a sua rede como {net}.": "We detected your network as {net}.",
    "Também aceita um IP, uma faixa (192.168.0.10-50) ou vários, separados por vírgula.":
        "Also accepts an IP, a range (192.168.0.10-50) or several, separated by commas.",
    "Nome do histórico": "History name",
    "Scans com o mesmo nome são comparados entre si.": "Scans with the same name are compared with each other.",
    "Comuns (86 portas, recomendado)": "Common (86 ports, recommended)",
    "Só web (HTTP/HTTPS)": "Web only (HTTP/HTTPS)",
    "Todas (65.535; bem mais lento)": "All (65,535; much slower)",
    "Testar serviços UDP": "Test UDP services",
    "Encontra SNMP, UPnP, mDNS, DNS e NTP. Acrescenta poucos segundos.": "Finds SNMP, UPnP, mDNS, DNS and NTP. Adds a few seconds.",
    "Procurar vulnerabilidades conhecidas (CVEs)": "Look up known vulnerabilities (CVEs)",
    "Consulta as bases públicas do NIST, da FIRST e do Ubuntu com o nome e a versão dos programas encontrados. "
    "Nenhum dado da sua rede é enviado.":
        "Queries the public NIST, FIRST and Ubuntu databases with the name and version of the software found. "
        "No data about your network is sent.",
    "Verificações externas": "External checks",
    "Pergunta ao Shodan o que a internet vê do seu IP público e confere se o DNS do roteador diz a verdade "
    "(usando o DNS da Cloudflare). Envia o seu IP público para esses dois serviços.":
        "Asks Shodan what the internet sees of your public IP and checks whether the router's DNS tells the truth "
        "(using Cloudflare's DNS). Sends your public IP to these two services.",
    "Modo cuidadoso": "Gentle mode",
    "Mais lento e leve. Use se câmeras, lâmpadas ou outros aparelhos baratos travarem durante o scan.":
        "Slower and lighter. Use it if cameras, bulbs or other cheap devices freeze during the scan.",
    "Testes ativos": "Active tests",
    "Tenta login anônimo no FTP, pergunta ao SSH quais logins aceita e procura arquivos sensíveis nos sites.":
        "Tries anonymous FTP login, asks SSH which logins it accepts and looks for sensitive files on websites.",
    "Aparece nos logs dos aparelhos como tentativa de acesso: use só em equipamentos seus.":
        "Shows up in device logs as access attempts: use only on your own equipment.",
    "Iniciar scan": "Start scan",
    "Descoberta": "Discovery",
    "Serviços": "Services",
    "Análise": "Analysis",
    "Procurando aparelhos…": "Looking for devices…",
    "Verificando portas abertas…": "Checking open ports…",
    "Identificando serviços…": "Identifying services…",
    "Analisando riscos…": "Analyzing risks…",
    "Encontrados": "Found",
    "Pronto em {s}s": "Done in {s}s",
    "Scan concluído": "Scan complete",
    "Ver o painel": "See the dashboard",
    "Relatório completo": "Full report",
    "nenhum problema": "no problems",
    "Desde o scan anterior: {a} novo(s), {b} resolvido(s)": "Since the previous scan: {a} new, {b} resolved",
    "aparelho(s) inédito(s):": "never-seen device(s):",
    "alerta enviado": "alert sent",
    "Primeiro scan deste histórico: os próximos serão comparados com este.":
        "First scan in this history: the next ones will be compared with it.",
    "O scan falhou": "The scan failed",

    # ── update banner ──
    "Nova versão disponível: {v}": "New version available: {v}",
    "Baixe pela": "Download it from the",
    "página da release no GitHub": "release page on GitHub",
    "O tbm não baixa nem instala nada sozinho.": "tbm never downloads or installs anything by itself.",
    "Como conferir o arquivo baixado": "How to verify the downloaded file",
    "SHA-256 publicado para": "Published SHA-256 for",
    "Compare com": "Compare with",
    "Para provar que saiu do CI deste repositório:": "To prove it came from this repository's CI:",
    "Não verificar mais": "Stop checking",

    # ── device types (tbm/scout/classify.py) ──
    "roteador/modem": "router/modem",
    "computador Windows": "Windows computer",
    "computador Apple": "Apple computer",
    "computador": "computer",
    "celular Android": "Android phone",
    "celular Apple": "Apple phone",
    "celular/notebook": "phone/laptop",
    "tablet Apple": "Apple tablet",
    "dispositivo Apple": "Apple device",
    "impressora": "printer",
    "câmera/DVR": "camera/DVR",
    "caixa de som": "speaker",
    "caixa de som/AirPlay": "speaker/AirPlay",
    "caixa de som/tela Google": "speaker/Google display",
    "casa inteligente (HomeKit)": "smart home (HomeKit)",
    "casa inteligente (Matter)": "smart home (Matter)",
    "dispositivo embarcado (Linux)": "embedded device (Linux)",
    "servidor de mídia": "media server",
    "TV/Chromecast": "TV/Chromecast",
    "TV/streaming": "TV/streaming",

    # ── welcome ──
    "Bem-vindo": "Welcome",
    "Primeiros passos": "First steps",
    "Sua rede": "Your network",
    "Primeiro scan": "First scan",
    "Bem-vindo ao threeblindmice": "Welcome to threeblindmice",
    'Três "ratos" cuidam da sua rede: o Scout descobre os aparelhos, o Sniffer procura riscos e o Squeak dá uma '
    "nota, compara com o passado e avisa você quando algo muda.":
        'Three "mice" look after your network: Scout discovers the devices, Sniffer looks for risks and Squeak '
        "gives a grade, compares it with the past and tells you when something changes.",
    "Detectamos a sua rede como {net} (o computador está em {ip}).": "We detected your network as {net} (this computer is at {ip}).",
    "O primeiro scan leva uns 20 segundos e é passivo: só observa, sem tentar login em nada.":
        "The first scan takes about 20 seconds and is passive: it only observes, without trying to log in to anything.",
    "Como funciona": "How it works",
    "Scan": "Scan",
    "Descobre aparelhos e serviços e dá uma nota de 0 a 100.": "Discovers devices and services and gives a grade from 0 to 100.",
    "Telegram, ntfy ou Discord, só quando aparece algo inédito.": "Telegram, ntfy or Discord, only when something new shows up.",
    "Repete o scan sozinho, de tempos em tempos.": "Repeats the scan by itself, every so often.",
    "Fazer o primeiro scan": "Run the first scan",
    "Ver tudo o que o programa faz": "See everything the program does",
    "Depois do primeiro scan, a página inicial vira o painel de saúde da rede, e os passos de alertas e vigia "
    "ficam a um clique.":
        "After the first scan, the home page becomes the network health dashboard, and alerts and watch are one "
        "click away.",
}
