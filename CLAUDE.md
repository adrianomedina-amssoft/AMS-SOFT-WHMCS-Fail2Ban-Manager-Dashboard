# CLAUDE.md — AMS SOFT Fail2Ban Manager

## Visão Geral

Addon WHMCS que gerencia fail2ban via painel admin visual. Elimina a necessidade de SSH/terminal para operações de ban/unban, gerenciamento de jails, visualização de logs e análise de ameaças por IA (Claude/Anthropic).

**Status:** Em desenvolvimento (v2.0.0, MIT License)
**Autor:** AMS SOFT — https://www.amssoft.com.br

## Ambiente

- **WHMCS:** 8+ (addon module)
- **PHP:** 8.1+
- **SO:** Debian/Ubuntu (paths hard-coded para Debian)
- **Dependências sistema:** fail2ban, sudo
- **Autoloader:** PSR-4 customizado em `lib/Router.php` (não usa Composer)
- **Templates:** PHP puro (sem Smarty), `extract()` + `ob_start()`

## Estrutura

```
amssoft_fail2ban/
├── amssoft_fail2ban.php        # Entry point WHMCS (5 funções obrigatórias + migrações v2/v3)
├── hooks.php                   # Hooks: ClientLoginFailed, AdminUserLoginFailed, AfterCronJob (IA)
├── lib/
│   ├── Router.php              # Autoloader PSR-4 + roteamento + renderização de templates
│   ├── Fail2BanClient.php      # Wrapper sudo fail2ban-client (sanitização rigorosa)
│   ├── JailConfig.php          # Parser/escritor de jail.local (INI custom, backup antes de escrever)
│   ├── Database.php            # Queries Eloquent (logs, config KV, sugestões IA, deduplicação)
│   ├── Helper.php              # CSRF, session, flash, sanitização, criptografia AES-256-CBC
│   ├── LogParser.php           # Parser de /var/log/fail2ban.log (ban/unban events)
│   ├── LogViewer.php           # Leitura de logs com highlight (suspicious/error patterns)
│   ├── AIAnalyzer.php          # Integração API Anthropic (Claude) — análise + geração de failregex
│   ├── FilterManager.php       # Cria filtros (.conf) e jails para filtros gerados pela IA
│   └── AutoBanEngine.php       # Motor de ban automático (3 modos: suggestion/auto/threshold)
├── controllers/
│   ├── DashboardController.php # KPIs, gráficos Chart.js, status fail2ban
│   ├── IpsController.php       # Lista IPs banidos, ban/unban manual
│   ├── JailsController.php     # CRUD de jails, enable/disable/remove
│   ├── LogPathsController.php  # Mapeamento de logs por jail
│   ├── LogViewerController.php # Visualização de logs + análise inline por IA
│   ├── ReportsController.php   # Relatórios paginados + exportação CSV (UTF-8 BOM)
│   └── AIController.php        # Sugestões IA, configurações, criar filtros, aprovar/rejeitar
├── templates/                  # Templates PHP (layout.tpl + 9 páginas)
│   ├── layout.tpl              # Layout base com sidebar e warnings do sistema
│   ├── dashboard.tpl           # Dashboard com KPIs e gráficos
│   ├── ips.tpl                 # Lista de IPs banidos + modal de ban
│   ├── jails.tpl               # Lista de jails + modal de criação
│   ├── jail_edit.tpl           # Edição de jail individual
│   ├── logpaths.tpl            # Gerenciamento de log paths
│   ├── logviewer.tpl           # Visualizador de logs com highlight
│   ├── reports.tpl             # Relatórios com filtros
│   ├── ai_suggestions.tpl      # Fila de sugestões + histórico da IA
│   └── ai_settings.tpl         # Configurações da IA
├── assets/
│   ├── css/amssoft_fail2ban.css
│   ├── js/amssoft_fail2ban.js
│   └── js/chart.min.js         # Chart.js embutido (sem CDN)
├── setup/
│   ├── sudoers/amssoft_fail2ban       # Regras sudoers para www-data
│   └── fail2ban/
│       ├── filter.d/whmcs.conf        # Filtro fail2ban para WHMCS auth
│       └── jail.whmcs.conf            # Jail template para WHMCS
├── sql/
│   ├── install.sql                    # Schema de referência (execução real via Capsule)
│   └── uninstall.sql                  # Drop tables
├── docs/screenshots/                  # Screenshots para documentação
├── version.txt                        # Versão (1.0.0)
└── .gitignore
```

## Namespace e Autoloader

Namespace raiz: `AMS\Fail2Ban`

O autoloader em `lib/Router.php` mapeia:
- `AMS\Fail2Ban\*` → `lib/`
- `AMS\Fail2Ban\Controllers\*` → `controllers/`

**Importante:** Não usar Composer. O autoloader é registrado via `spl_autoload_register()` dentro de uma IIFE estática (executa uma única vez).

## Banco de Dados

3 tabelas (prefixo `mod_amssoft_fail2ban_`):

### mod_amssoft_fail2ban_logs
Log de eventos (ban/unban/manual_ban/manual_unban). Indexada por ip, jail, timestamp.

### mod_amssoft_fail2ban_config
Key-value store genérico. Usado para:
- Configurações da IA (`ai_api_key`, `ai_mode`, `ai_model`, `ai_prompt`, etc.)
- Watermarks de offset por log (`ai_log_offset.<md5>`)
- Logs customizados (`custom_log.<key>`)
- Chave de criptografia (`_enc_key`)

### mod_amssoft_fail2ban_ai_suggestions
Sugestões da IA com status (pending/approved/rejected/auto_executed). Inclui campos v3: `filter_name`, `failregex`, `filter_created_at`.

### Migrações
- **v2** (`amssoft_fail2ban_migrate_v2`): cria tabela ai_suggestions se não existir
- **v3** (`amssoft_fail2ban_migrate_v3`): adiciona colunas filter_name, failregex, filter_created_at

Ambas são idempotentes e executadas automaticamente em cada carregamento do módulo (`amssoft_fail2ban_output`).

## Hooks WHMCS

### hooks.php
1. **ClientLoginFailed** — escreve em `/var/log/whmcs_auth.log` (formato compatível com fail2ban regex)
2. **AdminUserLoginFailed** — idem para admins
3. **AfterCronJob** — executa análise automática da IA (respeita intervalo configurável, rate limit)

### Segurança nos hooks
- Validação de path do log (deve ser `/var/log/`, extensão `.log`/`.txt`, sem traversal)
- Sanitização de user (remove newlines, null bytes, `<>?\\`)
- IP validado com `filter_var(FILTER_VALIDATE_IP)`

## Integração com fail2ban

### Fail2BanClient
Executa `sudo fail2ban-client <cmd>`. Todos os valores externos são sanitizados antes de entrar no comando:
- **Jail:** regex `/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/` (previne flags CLI como `-h`)
- **IP:** `filter_var(FILTER_VALIDATE_IP)`
- **Comando:** construído internamente, nunca aceita input direto do usuário

### JailConfig
Parser customizado de INI para `/etc/fail2ban/jail.local`:
- Backup timestamped antes de cada escrita
- Escrita atômica via temp file + `copy()` (evita escrita parcial)
- Strip de control characters nos valores (previne INI injection)
- Permissões esperadas: `chown root:www-data`, `chmod 0664`

### FilterManager
Cria filtros fail2ban em `/etc/fail2ban/filter.d/`:
- Nome: prefixo `amsfb-`, sanitizado para `[a-z0-9-]`, max 50 chars
- Validação de failregex: cada linha testada com `preg_match()`, rejeita múltiplos `<HOST>` por linha
- Escrita via temp file + `sudo cp` (fallback se diretório não for gravável)
- Verificação tripla de jail existente: jail.local + jail.d/ + daemon em memória

### Sudoers
Arquivo `setup/sudoers/amssoft_fail2ban` concede NOPASSWD para:
- `fail2ban-client` (status, set banip/unbanip, reload, ping)
- `/bin/cp /tmp/amsfb_filter_* /etc/fail2ban/filter.d/amsfb-*` (criação de filtros pela IA)
- `/bin/chmod 644 /etc/fail2ban/filter.d/amsfb-*`
- `Defaults:www-data !requiretty`

## Integração com IA (Claude / Anthropic)

### AIAnalyzer
- Endpoint: `https://api.anthropic.com/v1/messages`
- Modelos suportados: `claude-haiku-4-5-20251001`, `claude-sonnet-4-6`, `claude-opus-4-6`
- Logs truncados em 200 linhas (configurável: 200/400/600/800/1000)
- Prompt customizável pelo admin (max 8000 chars)
- **Mitigação de prompt injection:** instruções no system prompt, logs em `<log_data>` com aviso explícito

### AutoBanEngine — 3 modos
1. **suggestion** — IA sugere, admin aprova manualmente
2. **auto** — IA analisa e bane imediatamente (requer confirmação explícita do admin)
3. **threshold** — IA aguarda N detecções em X minutos por severidade

### Deduplicação (2 camadas)
1. **Watermark por arquivo:** lê apenas bytes novos desde última análise (offset no banco)
2. **IP dedup:** ignora IPs já banidos no fail2ban + IPs com sugestão pendente

### Criação de filtros pela IA
- **Cenário A:** sugestão já tem failregex → cria filtro diretamente
- **Cenário B:** sem failregex mas com evidence → chama IA para gerar on-demand
- Filtro criado em `/etc/fail2ban/filter.d/amsfb-<nome>.conf`
- Jail criada em `jail.local` com nome `amsfb-<nome>`

### Criptografia da API Key
- AES-256-CBC com IV aleatório
- Chave de criptografia: 32 bytes aleatórios persistidos no banco (`_enc_key`)
- Formato: `base64(iv + ciphertext)`

## Configurações do Módulo (WHMCS admin)

| Campo | Default | Descrição |
|---|---|---|
| sudo_path | `/usr/bin/sudo` | Caminho do sudo |
| fail2ban_client | `/usr/bin/fail2ban-client` | Caminho do fail2ban-client |
| jail_local_path | `/etc/fail2ban/jail.local` | Caminho do jail.local |
| whmcs_log_path | `/var/log/whmcs_auth.log` | Log de autenticação WHMCS |
| enable_hooks | yes | Registrar falhas de login no log |

## Rotas (actions)

| Action | Controller | Tipo |
|---|---|---|
| dashboard | DashboardController | Página |
| ips | IpsController | Página + POST |
| jails | JailsController | Página + AJAX |
| jail_edit | JailsController | Página |
| logpaths | LogPathsController | Página + AJAX |
| reports | ReportsController | Página + CSV export |
| logviewer | LogViewerController | Página + AJAX |
| ai | AIController | Página + AJAX |
| ai_settings | AIController | Página + AJAX |

## AJAX Endpoints

Todas as requisições AJAX são:
- Detectadas via `HTTP_X_REQUESTED_WITH: XMLHttpRequest`
- Validadas com CSRF token (rotacionado após cada uso)
- Respondem com JSON

### Jails (action=jails)
- `do=enable` — habilita jail
- `do=disable` — desabilita jail
- `do=remove` — remove jail
- `do=reload_all` — reload geral do fail2ban

### IA (action=ai)
- `do=approve` — aprova sugestão (bane IP)
- `do=reject` — rejeita sugestão
- `do=run_now` — executa análise manual (rate limit: 60s)
- `do=ping_api` — testa conexão com API Anthropic
- `do=save_settings` — salva configurações da IA
- `do=create_filter` — cria filtro fail2ban a partir de sugestão

### Log Viewer (action=logviewer)
- `do=fetch_lines` — lê linhas do log
- `do=ban_ip` — bane IP inline
- `do=analyze` — analisa log com IA

### Log Paths (action=logpaths)
- `do=validate` — valida path do log

## Segurança

### Marcadores no código
Procurar por `[SEC-N]` nos comentários para encontrar cada medida de segurança:

- **[SEC-1]** Path validation do log WHMCS (traversal, prefixo, extensão)
- **[SEC-2]** Strip de control characters em valores de INI (previne injection)
- **[SEC-3]** Escrita atômica de jail.local via temp file
- **[SEC-4]** Sanitização de jail e IP no Fail2BanClient
- **[SEC-5]** Escape de SQL LIKE wildcards
- **[SEC-6]** `JSON_HEX_TAG` em dados dentro de `<script>`
- **[SEC-7]** Rotação de CSRF token após cada uso
- **[SEC-8]** Restrição de paths do LogViewer a `/var/log/`, `/var/www/html/`, `/tmp/`
- **[SEC-9]** Flag de confirmação para modo automático da IA
- **[SEC-10]** Rate limiting de análise manual (60s)
- **[SEC-11]** Limite de 8000 chars no prompt customizado
- **[SEC-12]** CSRF validado incondicionalmente em todas as requisições AJAX POST
- **[SEC-14]** Evitar `Capsule::raw()` com variável interpolada
- **[SEC-15]** Validação de status contra ENUM antes de UPDATE
- **[SEC-16]** Mitigação de prompt injection (system prompt + tags `<log_data>`)

## Problemas Conhecidos

| Problema | Solução |
|---|---|
| sudo não instalado | `apt-get install -y sudo` |
| fail2ban não instalado | `apt-get install -y fail2ban` |
| fail2ban não inicia (sshd sem log) | `[sshd] enabled = false` no jail.local |
| www-data sem sudo | Verificar `/etc/sudoers.d/amssoft_fail2ban` |
| "Erro ao criar jail" | `chown root:www-data jail.local && chmod 0664 jail.local` |
| "Falha ao criar arquivo de filtro" | Re-aplicar sudoers (v3 adicionou regras de cp/chmod) |
| Aviso "sudoers desatualizado" | Re-aplicar sudoers do setup/ |

## Instalação (resumo)

1. `apt-get install -y fail2ban sudo`
2. Copiar módulo para `modules/addons/amssoft_fail2ban/`
3. `chown -R www-data:www-data` + permissões 755/644
4. Copiar sudoers para `/etc/sudoers.d/amssoft_fail2ban` (chmod 0440)
5. Copiar filtro whmcs.conf para `/etc/fail2ban/filter.d/`
6. Configurar `jail.local` com jail `[whmcs]` e `[sshd] enabled = false`
7. `chown root:www-data /etc/fail2ban/jail.local && chmod 664`
8. Criar `/var/log/whmcs_auth.log` (chown www-data)
9. `systemctl restart fail2ban`
10. Ativar módulo em WHMCS Admin → Módulos Addon

## Regras de Desenvolvimento

- **Não usar Composer** — autoloader customizado em Router.php
- **Não alterar arquivos ionCoded do WHMCS**
- **Sempre criar backup** antes de alterar jail.local (JailConfig faz isso automaticamente)
- **Sanitização obrigatória** — todo input externo deve ser sanitizado antes de uso em comandos shell, SQL, ou arquivos
- **Escrita atômica** — usar temp file + copy() para arquivos críticos
- **Templates PHP puros** — sem Smarty, sem Blade, sem Twig
- **CSS/JS embutido** — sem CDN externo, Chart.js local
- **CSRF em todas as operações POST/AJAX**
- **JSON_HEX_TAG** em dados inseridos em HTML
