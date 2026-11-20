# Política de segurança

O threeblindmice é uma ferramenta de segurança, então leva a sério as falhas no próprio código.

## Versões com suporte

Correções de segurança saem para a versão mais recente publicada no PyPI. Use sempre a última.

## Como relatar uma vulnerabilidade

**Não abra uma issue pública** para falhas de segurança. Em vez disso:

- Use **Report a vulnerability** na aba **Security** do repositório no GitHub (GitHub Security Advisories), ou
- abra uma issue pedindo um canal privado de contato, sem detalhes da falha.

Inclua, se possível: versão do tbm, sistema operacional, passos para reproduzir e o impacto. Um exemplo mínimo ajuda muito.

### O que esperar

- **Resposta inicial:** em até 7 dias.
- **Correção:** falhas confirmadas são corrigidas o quanto antes; as graves têm prioridade.
- **Crédito:** quem relata é creditado na nota da versão, se quiser.

## Escopo

Interessam especialmente:

- execução de código a partir de dados da rede (nomes mDNS/SSDP, respostas UPnP, banners de serviço);
- qualquer coisa que faça o tbm sair do escopo autorizado (SSRF, escanear hosts fora do escopo);
- vazamento do token de sessão da interface, dos segredos de alerta ou do histórico;
- os parsers binários próprios (DNS, SNMP, DHCP, NBNS): a entrada vem da rede e é tratada como hostil.

## Fora de escopo

- Falta de rede-limite nos scans (é uma ferramenta de scan, por natureza).
- Avisos de antivírus sobre o instalador do Windows (é um falso positivo conhecido de programas feitos com PyInstaller; confira o SHA-256 e o atestado de origem).
- Relatórios gerados por scanners automáticos sem um caso concreto de exploração.

## Boas práticas que o projeto já adota

- Escopo imposto em duas camadas: só redes privadas, revalidado antes de qualquer check.
- A interface escuta só em `127.0.0.1`, com token de sessão, proteção contra CSRF e DNS rebinding.
- Nenhum teste ativo (tentativa de conexão a serviços) roda sem `--active` explícito.
- O tbm **não tenta adivinhar senhas**: só detecta serviços que não exigem autenticação.
- Cadeia de suprimentos travada: dependências com hash, só wheels, imagens por digest, Actions por SHA, atestados SLSA e SBOM nas releases (veja o README).
