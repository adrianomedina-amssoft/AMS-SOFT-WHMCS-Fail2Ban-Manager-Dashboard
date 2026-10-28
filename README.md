# AMS SOFT — Fail2Ban Manager para WHMCS

Painel administrativo para Fail2Ban, com proteção nativa, análise assistida por IA, evidências por IP e controles de automação. Versão pública: **2.2.55**.

Este projeto altera regras de segurança quando configurado para isso. Teste em homologação e mantenha acesso de recuperação antes de instalar ou atualizar. Não é uma garantia de detecção de todos os ataques.

## Novidades da 2.2.55

- Novo grupo opcional `session_lfi_probe` em **Proteção → Sondagem nativa**: reconhece apenas `/vuln.php?page=/tmp/sessions/sess_...`, com nome de sessão limitado e barras literais ou codificadas. Não transforma qualquer PHP, query ou 404 em ataque. Vem desmarcado por padrão; ative somente após conferir ausência de uso legítimo em todos os sites monitorados. Usa os controles nativos de tentativas, janela, duração e whitelist.
- Validação de novos filtros recusa expressões iniciadas por um prefixo arbitrário antes do IP. Testes reproduzem captura truncada do endereço e exigem o peer real, incluindo IPv6 e campos forjados.
- `scripts/legacy_peer_repair.py` fornece uma transformação pura e delimitada dos cabeçalhos de cinco filtros legados. Não é um instalador: não grava configuração nem recarrega jails. Uma aplicação operacional exige revisar os filtros existentes, comparar hashes, testar os ramos, preservar tickets e ações e conferir a cobertura após reload. Copiar esta versão não repara automaticamente filtros já instalados em `/etc/fail2ban`.

Regras aprendidas e ajustes de um servidor, inclusive ampliações de fontes ou de cobertura de `/admin/config.php`, não são distribuídos como configuração pronta. A atualização não transfere bans, não reprocessa eventos antigos e não altera automaticamente os limites da IA. Atualize também a ponte privilegiada conforme as instruções abaixo antes de selecionar o novo grupo.

## Como funciona

O Fail2Ban atende primeiro os vetores cobertos pelas regras nativas. A IA complementa essa proteção com análise de comportamentos e propostas fundamentadas em evidências individuais. O cron do WHMCS executa a automação; não é necessário manter o painel aberto.

- **Sondagem nativa:** catálogo de assinaturas específicas, incluindo `.env`, Git, traversal e grupos opcionais de aplicações. Tentativas, janela e duração do ban são ajustáveis. Habilite apenas grupos incompatíveis com o uso legítimo dos sites monitorados.
- **IA:** provedores Anthropic, OpenAI e MiMo, com modos, confirmação de automação, confiança mínima, limites de consumo e orçamento de ciclo. Receber uma sugestão não significa que o IP foi bloqueado.
- **Validação:** a decisão precisa cumprir política, whitelist, recência, origem e prova individual. Cobertura de firewall é diferente de existir um ticket de ban.
- **Economia de tokens:** IPs com cobertura comprovada e whitelist são retirados dos candidatos; há rechecagem antes do envio ao provedor. Cobertura desconhecida não é tratada como proteção confirmada.
- **Aprendizado:** propostas de filtros passam por critérios próprios e validação nativa. Não é criado um filtro automaticamente apenas porque vários IPs acessaram a mesma URL.
- **Painel:** dashboard, IPs, jails, caminhos de logs, relatórios, visualizador, decisões da IA, configurações e proteção adaptativa.

O ban nativo é assíncrono: a requisição que gera o log pode receber resposta antes do bloqueio. Um `404`, User-Agent automatizado ou rota legítima, isoladamente, não comprova ataque. Uma rota legítima também não torna um payload ofensivo inofensivo.

## Requisitos e limites de implantação

- WHMCS 8+, PHP 8.1+ e suas dependências usuais.
- Linux com Fail2Ban, Python 3, sudo e acesso administrativo ao servidor.
- Os exemplos usam Debian/Ubuntu, Apache, `www-data` e `/var/www/html/whmcs`. Adapte-os ao ambiente.
- A verificação de cobertura depende das ações e do backend de firewall suportados pelo código; configurações não reconhecidas devem permanecer como desconhecidas.
- Os caminhos de logs permitidos e alguns pares de access/error log são explícitos no código e na ponte. Uma implantação com nomes diferentes exige adaptação e testes, não apenas cadastro no visualizador.
- Reverse proxy/CDN requer configuração correta e confiável do IP de origem. Não confie indiscriminadamente em cabeçalhos fornecidos pelo cliente.

Este repositório distribui código, esquema de referência, testes e exemplos. Não contém banco WHMCS, chaves de API, configuração do servidor, logs reais, listas de ban, backups ou relatórios internos. Exemplos específicos foram substituídos por endereços fictícios; não são configurações prontas para o seu servidor.

## Instalação e atualização

Faça backup **privado** do banco, módulo e configuração Fail2Ban. Planeje atualização em janela controlada; não sobrescreva `jail.local`, whitelist ou regras existentes com exemplos deste repositório.

1. Copie o conteúdo para `modules/addons/amssoft_fail2ban` dentro do WHMCS, sem `.git` e sem artefatos locais. Mantenha o código sob controle administrativo; permita escrita web somente onde o funcionamento exigir, como os locks de runtime.
2. Bloqueie acesso HTTP aos diretórios internos. Há `.htaccess` e um exemplo de configuração de servidor em `setup/apache/amssoft_fail2ban.conf`. Com `AllowOverride None` ou Nginx, a proteção precisa ser configurada no servidor. Confira também a negação a dotfiles, backups, testes e scripts.
3. Instale a ponte privilegiada e suas dependências, como root, antes de ativar os consumidores desta versão. Para o caminho de exemplo:

```bash
install -d -o root -g root -m 0755 /usr/local/lib/amssoft_fail2ban
install -o root -g root -m 0755 /var/www/html/whmcs/modules/addons/amssoft_fail2ban/scripts/audit.py /usr/local/lib/amssoft_fail2ban/audit.py
install -o root -g root -m 0644 /var/www/html/whmcs/modules/addons/amssoft_fail2ban/scripts/firewall_state.py /usr/local/lib/amssoft_fail2ban/firewall_state.py
install -o root -g root -m 0755 /var/www/html/whmcs/modules/addons/amssoft_fail2ban/setup/amsfb-admin /usr/local/sbin/amsfb-admin
```

4. Revise `setup/sudoers/amssoft_fail2ban`, ajuste o usuário web se necessário e valide com `visudo -cf` antes de instalar uma cópia root:root, modo `0440`, em `/etc/sudoers.d/amssoft_fail2ban`. Execute `visudo -c` após a instalação. Não conceda escrita web em `/etc/fail2ban` nem comandos sudo genéricos de cópia, shell ou alteração de permissões.
5. Revise `setup/fail2ban/filter.d/whmcs.conf` e `setup/fail2ban/jail.whmcs.conf` antes de incorporar a configuração ao Fail2Ban. Prepare o log de autenticação com permissões adequadas. Valide com `fail2ban-client -t`; qualquer reload deve preservar as regras e bans existentes.
6. Ative o addon e configure o acesso administrativo no WHMCS. Na atualização, execute as migrações pelo fluxo suportado; o comando administrativo é `php modules/addons/amssoft_fail2ban/scripts/runtime.php migrate`, a partir da raiz do WHMCS, como root. Migrações alteram o banco: não são um teste de leitura. O esquema SQL de referência não substitui as migrações.
7. Confira o cron do WHMCS, permissões de leitura/coleta, fontes e estado da ponte. A tela de Log Paths não ativa coleta ou jails por si só. Verifique também os logs dos redirecionamentos HTTP, não apenas HTTPS.
8. Configure provedor e chave pela UI, revise whitelist e políticas e só então confirme a automação desejada. Instalar este repositório não transfere as configurações nem habilita automaticamente a operação de outra instalação.

Os arquivos em `setup/rsyslog` são exemplos opcionais. O destino `graylog.example.invalid` é fictício e deve ser substituído antes de qualquer uso. Não habilite envio de logs a terceiros sem revisar destino e conteúdo.

## Ajustes pela interface

Em **Proteção**, revise grupos de sondagem, critérios comportamentais, recência, limites de fila/ciclo, aprendizado e manutenção. Em **Configurações da IA**, configure provedor, credenciais, whitelist e prompt. A prévia local do prompt não chama o provedor; o teste de conexão pode consumir tokens e exige confirmação.

Na análise de manipulação de query, a janela de repetição é separada da idade máxima da evidência. Os padrões são três eventos em cinco minutos e prazo de decisão de trinta minutos, limitado pela atividade recente global. Esses limites não substituem a classificação ofensiva e a validação individual. Intervalo, orçamento, coleta e fila podem fazer uma evidência vencer antes da decisão.

Limpeza, desbloqueio e monitoramento são ações administrativas explícitas. Não execute manutenção apenas para zerar indicadores. Histórico de decisões e contadores de eventos não equivalem a bans ativos.

## Testes

Exemplos de suítes locais sem bootstrap do WHMCS, banco ou chamadas ao provedor:

```bash
php tests/query_probe.php
php tests/policy.php
php tests/protection_view.php
php tests/ai_settings.php
node tests/protection_ui.js
node tests/ai_settings_ui.js
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_*.py'
```

Os testes Python precisam dos módulos Python do Fail2Ban. Use o interpretador compatível com a instalação da distribuição. Os testes JavaScript precisam de Node.js; ele não é necessário para servir o módulo.

**Não execute todos os arquivos de `tests/` ou `scripts/` indiscriminadamente em produção.** Há testes de integração que acessam banco, namespaces/firewall ou HTTP e comandos de manutenção que alteram estado. Use ambiente descartável e revise cada entrada. Scripts legados de reparo não fazem parte da instalação normal; a seleção de IDs auditados de uma instalação foi removida da distribuição pública e exige preparação local explícita.

## Segurança e publicação

Consulte [SECURITY.md](SECURITY.md) antes de compartilhar diagnósticos, screenshots ou dumps. O `.gitignore` é uma proteção auxiliar, não uma garantia contra publicação de segredos já rastreados.

O resumo público das mudanças está em [CHANGELOG.md](CHANGELOG.md). PRDs operacionais e evidências reais ficam fora desta distribuição.

## Contribuições e licença

Abra issues com reprodução mínima e dados fictícios, sem credenciais ou registros de clientes. Para problemas que revelem dados sensíveis, não use uma issue pública.

Licença MIT, conforme a declaração já existente no projeto. Mantenha os créditos **AMS SOFT** — [www.amssoft.com.br](https://www.amssoft.com.br).
