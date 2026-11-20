"""Catálogo de funcionalidades em linguagem simples, para a página "Funcionalidades"."""

from __future__ import annotations

from dataclasses import dataclass

from tbm.sniffer import REGISTRY


@dataclass(frozen=True)
class CheckInfo:
    what: str  # o que verifica
    why: str  # por que importa


CHECKS: dict[str, CheckInfo] = {
    "service.exposed": CheckInfo(
        "Serviços abertos que costumam ser alvo: Telnet, SMB, RDP, bancos de dados, Docker, ADB…",
        "Cada porta aberta é uma porta de entrada. A severidade muda conforme o serviço está na "
        "sua rede ou exposto à internet."),
    "service.banner": CheckInfo(
        "Fraquezas que o próprio serviço revela ao se apresentar (Redis sem senha, SSH versão 1).",
        "Algumas falhas são visíveis só pelo cumprimento inicial do serviço, sem precisar testar nada."),
    "service.ajp": CheckInfo(
        "Conector AJP do Tomcat aberto, confirmado pelo próprio protocolo (CPing/CPong).",
        "Permite ler arquivos da aplicação (Ghostcat). Confirmamos antes de acusar porque a mesma "
        "porta 8009 é usada pelo Google Cast."),
    "service.ftp-anon": CheckInfo(
        "Se o servidor FTP aceita login anônimo, sem senha.",
        "Qualquer um da rede pode listar, baixar ou até enviar arquivos."),
    "ssh.algorithms": CheckInfo(
        "Algoritmos de criptografia que o SSH aceita e a falha Terrapin.",
        "Algoritmos antigos (SHA-1, CBC, DH de 1024 bits) enfraquecem a proteção da conexão."),
    "ssh.auth": CheckInfo(
        "Se o SSH aceita login por senha (ou, pior, sem credencial nenhuma).",
        "Senhas sofrem força bruta o tempo todo. O ideal é aceitar só chaves."),
    "smb.negotiate": CheckInfo(
        "SMBv1 ligado e assinatura de pacotes SMB não obrigatória.",
        "O SMBv1 é o que o WannaCry explorou. Sem assinatura obrigatória, ataques de NTLM relay "
        "ficam viáveis."),
    "tls.config": CheckInfo(
        "Certificados expirados, autoassinados ou com chave fraca, e protocolos TLS antigos.",
        "Certificado ruim ensina as pessoas a ignorar avisos de segurança, e TLS antigo é "
        "vulnerável a downgrade."),
    "http.passive": CheckInfo(
        "Headers de segurança, cookies sem proteção, versão exposta, listagem de diretório e "
        "login sem HTTPS.",
        "São as configurações básicas que impedem XSS, clickjacking e roubo de sessão."),
    "http.paths": CheckInfo(
        "Arquivos sensíveis esquecidos no servidor web: .git, .env, phpinfo, actuator…",
        "Um .env exposto costuma conter senhas de banco e chaves de API."),
    "http.open-api": CheckInfo(
        "APIs administrativas sem autenticação (Docker, Elasticsearch, CouchDB).",
        "A API do Docker aberta equivale a dar acesso de administrador da máquina."),
    "udp.services": CheckInfo(
        "Serviços UDP: SNMP com senha padrão, UPnP, mDNS, DNS e NTP.",
        "SNMP com 'public' entrega toda a configuração do equipamento, e UPnP deixa programas "
        "abrirem portas no roteador."),
    "upnp.igd": CheckInfo(
        "Quais portas o roteador abriu para a internet via UPnP, e para qual aparelho.",
        "Responde à pergunta mais importante numa rede doméstica: o que da minha casa está "
        "exposto à internet?"),
    "cve.nvd": CheckInfo(
        "Vulnerabilidades conhecidas (CVEs) das versões de software encontradas.",
        "Prioriza pelo que está sendo explorado de verdade (CISA KEV e EPSS), e não só pela nota "
        "CVSS. Também descarta CVEs que a distro já corrigiu."),
    "secrets.local": CheckInfo(
        "Senhas, tokens e chaves privadas esquecidos em código e arquivos de configuração.",
        "Credencial em código acaba em backup, repositório e imagem de container."),
    "network.wifi": CheckInfo(
        "A criptografia da rede Wi-Fi em que este computador está: aberta, WEP, WPA, WPA2 ou WPA3.",
        "Wi-Fi fraco deixa qualquer vizinho entrar na rede, e a partir daí todos os outros testes importam."),
    "network.ipv6": CheckInfo(
        "Aparelhos com endereço IPv6 público e portas que também respondem pelo IPv6.",
        "No IPv6 não há NAT: se o firewall IPv6 do roteador estiver desligado, essas portas ficam "
        "expostas à internet."),
    "network.dns": CheckInfo(
        "Se o DNS do roteador e do computador respondem a verdade (só com Verificações externas).",
        "Roteador invadido troca o DNS para mandar você a sites falsos de banco, mesmo digitando o "
        "endereço certo."),
    "network.external": CheckInfo(
        "O que a internet vê do seu IP público, segundo o Shodan (só com Verificações externas).",
        "É a visão do atacante: portas que qualquer um alcança de fora, sem precisar estar na sua rede."),
    "network.default-pass": CheckInfo(
        "Lembra de conferir a senha de administração de roteadores e câmeras (não testa senha nenhuma).",
        "Senha de fábrica é pública e é um dos primeiros alvos numa rede doméstica."),
    "iot.rtsp": CheckInfo(
        "Se a câmera entrega o vídeo (RTSP) sem pedir senha.",
        "Câmera sem senha deixa qualquer um assistir ao vivo."),
    "iot.mqtt": CheckInfo(
        "Se o broker MQTT da casa inteligente aceita conexão anônima.",
        "Sem senha, qualquer um lê o estado da casa e manda comandos (abrir, ligar, desligar)."),
    "network.evil-twin": CheckInfo(
        "Uma rede Wi-Fi aberta usando o mesmo nome da sua (golpe do gêmeo maligno).",
        "Seus aparelhos podem se conectar a ela por engano e entregar o tráfego ao atacante."),
    "network.rogue-dhcp": CheckInfo(
        "Mais de um servidor DHCP respondendo na rede.",
        "Um DHCP intruso entrega gateway ou DNS falso e intercepta o tráfego."),
    "iot.services": CheckInfo(
        "Serviços de casa conectada visíveis: impressora na 9100, Home Assistant, gravadores de câmera.",
        "Alguns desses aparelhos têm falhas conhecidas e nunca deveriam ficar expostos à internet."),
}


@dataclass(frozen=True)
class Feature:
    title: str
    description: str
    cli: str
    link: str | None = None


TOOLS: list[Feature] = [
    Feature("Novo scan", "Descobre os aparelhos da rede, testa os serviços e dá uma nota de 0 a 100.",
            "tbm scan 192.168.0.0/24 --label casa --udp", "/scan"),
    Feature("Achados e riscos aceitos", "Lista o que foi encontrado. O que você não pode corrigir "
            "(ex.: o modem da operadora) pode ser aceito com prazo e sai da nota.",
            "tbm accept <id> -l casa -r \"motivo\" --until 2027-01-01", "/findings"),
    Feature("Dispositivos", "Inventário com MAC, fabricante, tipo e histórico de cada aparelho. "
            "Um aparelho que troca de IP continua sendo o mesmo.", "tbm dashboard", "/inventory"),
    Feature("O que mudou", "Compara com o scan anterior: aparelhos novos, portas abertas, achados "
            "novos e resolvidos.", "tbm diff <scan_antigo> <scan_novo>"),
    Feature("Alertas", "Avisa no Telegram, ntfy, Discord ou Slack só quando aparece algo inédito.",
            "tbm telegram-setup  ·  tbm notify-test", "/alerts"),
    Feature("Vigia automático", "Agenda o scan no Windows/Linux para rodar sozinho, sem abrir janela.",
            "tbm schedule install 192.168.0.0/24 -l casa --every 6h --udp", "/watch"),
    Feature("Carta para o provedor", "Gera o texto do chamado com os problemas do modem da operadora.",
            "tbm letter 192.168.100.175 -l casa -o chamado.txt", "/letter"),
    Feature("Segredos em código", "Procura senhas e tokens esquecidos numa pasta.", "tbm secrets C:\\projeto"),
]


def catalog() -> list[dict[str, str]]:
    from tbm.plugins import ORIGINS, load_plugins

    load_plugins()
    rows = []
    for cid, cls in sorted(REGISTRY.items()):
        info = CHECKS.get(cid, CheckInfo(cls.what or cls.name, cls.why))
        mode = "ativo" if cls.active_only else ("com --secrets" if cid == "secrets.local" else "passivo")
        rows.append({"id": cid, "name": cls.name, "mode": mode, "what": info.what, "why": info.why,
                     "origin": ORIGINS.get(cid, "")})
    return rows
