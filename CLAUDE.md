# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

**Idioma:** Pense, raciocine e converse sempre em português brasileiro. Todo o raciocínio interno, explicações e comunicação com o usuário devem ser em PT-BR. Código, commits e variáveis permanecem em inglês.

## Visão Geral

Addon WHMCS que gerencia fail2ban via painel admin visual. Elimina a necessidade de SSH/terminal para operações de ban/unban, gerenciamento de jails, visualização de logs e análise de ameaças por IA (multi-provider: Anthropic, MiMo/Xiaomi, e qualquer provedor OpenAI-compatible futuro).

**Status:** Em desenvolvimento (v2.0.1, MIT License)
**Autor:** AMS SOFT — https://www.amssoft.com.br

## Ambiente

- **WHMCS:** 8.13.1 (ionCoded, não modificar vendor/)
- **PHP:** 8.2.31 (CLI e Apache)
- **SO:** Debian 12 (Bookworm) — paths hard-coded para Debian
- **Dependências sistema:** fail2ban, sudo
- **Autoloader:** PSR-4 customizado em `lib/Router.php` (não usa Composer)
- **Templates:** PHP puro (sem Smarty), `extract()` + `ob_start()`
- **Detalhes do ambiente WHMCS (crontab, data dir, addons):** ver [`/var/www/html/whmcs/CLAUDE.md`](../../CLAUDE.md)

## Trabalhando neste Repo

Este é um addon WHMCS — não há build step, não há Composer, não há npm. Os arquivos são carregados diretamente pelo framework WHMCS.

### Quick Start (novo desenvolvedor)

```
amssoft_fail2ban.php  → entry point WHMCS (activate, deactivate, migrations)
hooks.php             → 3 hooks (ClientLoginFailed, AdminUserLoginFailed, AfterCronJob)
lib/Router.php        → autoloader + roteamento (tudo começa aqui)
lib/AIAnalyzer.php    → multi-provider IA (Anthropic, MiMo) — o coração do módulo
lib/AutoBanEngine.php → motor de ban automático (3 modos)
lib/FilterManager.php → cria filtros/jails fail2ban via IA
lib/Database.php      → todas as queries (Eloquent/Capsule)
controllers/AIController.php → maior controller (~54K), endpoints AJAX da IA
templates/ai_suggestions.tpl → maior template (~70K), UI de sugestões + seleção cross-page
```

**Fluxo principal:** Login falha → hook escreve no log → cron (a cada 4min) → `AutoBanEngine::runAnalysis()` → `AIAnalyzer` lê log → API IA → sugestões salvas → admin aprova/bane.

### Common Tasks

**Test a PHP syntax error:**
```bash
php -l lib/AIAnalyzer.php
```

**Test the module loads without fatal errors** (requires WHMCS + DB):
```bash
php -r "require '/var/www/html/whmcs/vendor/autoload.php'; require 'amssoft_fail2ban.php'; echo 'OK\n';"
```

**Check fail2ban and sudo are working:**
```bash
sudo fail2ban-client ping          # expect: pong
sudo fail2ban-client status whmcs  # expect: jail info
```

**View the auth log (what the module writes):**
```bash
tail -f /var/log/whmcs_auth.log
```

**Validate sudoers syntax after editing:**
```bash
visudo -c
```

**Apply sudoers from setup/ to the system:**
```bash
cp setup/sudoers/amssoft_fail2ban /etc/sudoers.d/amssoft_fail2ban
chmod 0440 /etc/sudoers.d/amssoft_fail2ban
visudo -c
```

**Check WHMCS cron is running the AI hook:**
```bash
# The AfterCronJob hook fires after each WHMCS cron run (every 4 min per crontab)
# Check ai_last_run in the config table to see last execution
mysql -u whmcs -p whmcs -e "SELECT * FROM mod_amssoft_fail2ban_config WHERE key='ai_last_run';"
```

### No Tests

There is no test suite. Validation is manual: load the addon in WHMCS admin, exercise each page, check fail2ban commands work via sudo.

### Debugging (queries úteis)

```bash
# Ver sugestões pendentes da IA
mysql -u whmcs -p whmcs -e "SELECT id, ip, severity, confidence, status, threat FROM mod_amssoft_fail2ban_ai_suggestions WHERE status='pending' ORDER BY created_at DESC LIMIT 20;"

# Ver configurações da IA (provedor ativo, modelo, intervalo)
mysql -u whmcs -p whmcs -e "SELECT key, LEFT(value,80) as value FROM mod_amssoft_fail2ban_config WHERE key LIKE 'ai_%' ORDER BY key;"

# Verificar watermark de um log específico
mysql -u whmcs -p whmcs -e "SELECT key, value FROM mod_amssoft_fail2ban_config WHERE key LIKE 'ai_log_offset%';"

# Verificar rate limit GeoIP
mysql -u whmcs -p whmcs -e "SELECT key, value FROM mod_amssoft_fail2ban_config WHERE key LIKE 'geoip_%';"

# Últimos eventos de ban registrados
mysql -u whmcs -p whmcs -e "SELECT ip, jail, action, timestamp FROM mod_amssoft_fail2ban_logs ORDER BY timestamp DESC LIMIT 20;"

# Verificar se a chave de criptografia existe
mysql -u whmcs -p whmcs -e "SELECT key, LENGTH(value) as len FROM mod_amssoft_fail2ban_config WHERE key='_enc_key';"

# Verificar status do cache GeoIP (contagem e idade)
mysql -u whmcs -p whmcs -e "SELECT COUNT(*) as total, MIN(updated_at) as oldest, MAX(updated_at) as newest FROM mod_amssoft_fail2ban_geo_cache;"
```

### File Edit Workflow

1. Edit the PHP file directly (no compilation needed)
2. Run `php -l` on the file to catch syntax errors
3. Refresh the WHMCS admin page to see changes
4. For hooks.php changes: changes take effect on the next WHMCS cron run or next login failure event

### Key Constraints

- **No Composer** — the custom autoloader in `lib/Router.php` handles class loading. Never run `composer install` or add a `composer.json`.
- **No external CDNs** — Chart.js is bundled in `assets/js/chart.min.js`. CSS is in `assets/css/amssoft_fail2ban.css`.
- **No Smarty/Twig/Blade** — templates are raw PHP with `extract()` + `ob_start()`.
- **Ioncube-encoded WHMCS** — never modify files under `vendor/whmcs/whmcs-foundation/`.
- **Database** — uses WHMCS's Eloquent via `WHMCS\Database\Capsule`. No separate DB connection.

## Estrutura

```
amssoft_fail2ban/
├── amssoft_fail2ban.php        # Entry point WHMCS (5 funções obrigatórias + migrações v2/v3/v4)
├── hooks.php                   # Hooks: ClientLoginFailed, AdminUserLoginFailed, AfterCronJob (IA)
├── lib/
│   ├── Router.php              # Autoloader PSR-4 + roteamento + renderização de templates
│   ├── Fail2BanClient.php      # Wrapper sudo fail2ban-client (sanitização rigorosa)
│   ├── JailConfig.php          # Parser/escritor de jail.local (INI custom, backup antes de escrever)
│   ├── Database.php            # Queries Eloquent (logs, config KV, sugestões IA, deduplicação)
│   ├── Helper.php              # CSRF, session, flash, sanitização, criptografia AES-256-CBC
│   ├── LogParser.php           # Parser de /var/log/fail2ban.log (ban/unban events)
│   ├── LogViewer.php           # Leitura de logs com highlight + readNewLinesFromOffset() + filterLinesByIPs() pre-filter
│   ├── AIAnalyzer.php          # Integração multi-provider IA (Anthropic, MiMo) — análise + geração de failregex
│   ├── FilterManager.php       # Cria filtros (.conf) e jails para filtros gerados pela IA
│   ├── AutoBanEngine.php       # Motor de ban automático (3 modos: suggestion/auto/threshold)
│   ├── LogLock.php             # Lock cross-user (cron root ↔ painel www-data) via setgid
│   ├── GeoIP.php               # Lookup geográfico via ip-api.com (cache + rate limiting)
│   ├── TruncatedResponseException.php # Exceção para resposta truncada por max_tokens
│   └── InvalidResponseException.php  # Exceção para resposta que não é JSON válido
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
│   ├── ai_suggestions.tpl      # Fila de sugestões + histórico + seleção cross-page por país
│   └── ai_settings.tpl         # Configurações da IA
├── data/
│   ├── .htaccess                    # Deny from all (bloqueia acesso HTTP)
│   └── locks/
│       ├── .gitkeep                 # Mantém diretório no repo
│       └── *.lock                   # Lock files (ignorados pelo .gitignore)
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
├── CHANGELOG.md                       # Histórico de mudanças e bugs corrigidos
├── version.txt                        # Versão (2.0.1)
└── .gitignore
```

## Namespace e Autoloader

Namespace raiz: `AMS\Fail2Ban`

O autoloader em `lib/Router.php` mapeia:
- `AMS\Fail2Ban\*` → `lib/`
- `AMS\Fail2Ban\Controllers\*` → `controllers/`

**Importante:** Não usar Composer. O autoloader é registrado via `spl_autoload_register()` dentro de uma IIFE estática (executa uma única vez).

## Banco de Dados

4 tabelas (prefixo `mod_amssoft_fail2ban_`):

### mod_amssoft_fail2ban_logs
Log de eventos. Indexada por ip, jail, timestamp. Actions (ENUM): `ban`, `unban`, `manual_ban`, `manual_unban`, `jail_created` (auto-criação), `auto_filter_fallback` (fallback para ai-bans), `auto_filter_error` (erro na auto-criação), `auto_filter_dedup` (similaridade ≥65% no fluxo automático — reusa filtro existente), `auto_filter_orphan` (filtro órfão limpo com sucesso), `auto_filter_orphan_cleanup_failed` (falha ao limpar órfão), `analysis_locked` (log bloqueado por outro processo durante análise concorrente), `lock_config_warning` (diretório de lock com grupo incorreto — modo degradado ativo).

### mod_amssoft_fail2ban_config
Key-value store genérico. Usado para:
- **Multi-provider IA:**
  - `ai_active_provider` — provedor ativo (`anthropic` | `mimo`)
  - `ai_provider_{name}_api_key` — chave API criptografada por provedor
  - `ai_provider_{name}_model` — modelo selecionado por provedor
  - `ai_provider_{name}_base_url` — endpoint (provedores editáveis)
  - `ai_provider_{name}_last_ping` — último ping OK por provedor
  - `ai_provider_mimo_protocol` — legado, limpo pela migração v6 (protocolo fixo OpenAI)
- **Config compartilhada IA:** `ai_mode`, `ai_prompt`, `ai_interval_minutes`, `ai_min_confidence`, `ai_whitelist_ips`, `ai_auto_enabled`, `ai_log_lines`, `ai_threshold_*`
- **Auto-criação de filtro/jail:** `ai_auto_create_filter` (yes/no), `ai_auto_create_min_occurrences` (int, default 3), `ai_auto_create_min_distinct_ips` (int, default 2), `ai_auto_create_window_days` (int, default 30), `ai_auto_max_jails_per_day` (int, default 5), `ai_auto_jails_created_today` (contador), `ai_auto_jails_created_date` (data do reset)
- **Bantime global:** `global_bantime` (segundos, default 604800 = 7 dias)
- **Confirmação auto:** `ai_confirmed_auto` (flag, necessário para modos auto/threshold)
- **Legado (migrado automaticamente):** `ai_api_key`, `ai_model`
- Watermarks de offset por log (`ai_log_offset.<md5>`)
- Sessão de análise (`ai_analysis_session_start` — timestamp, expira em 300s)
- Rate limiting IA (`ai_last_run` — timestamp, 60s entre análises)
- Rate limiting GeoIP: `geoip_requests_this_minute` (contador), `geoip_minute_window_start` (timestamp da janela), `geoip_cooldown_until` (timestamp do cooldown 429)
- Logs customizados (`custom_log.<key>`)
- Chave de criptografia (`_enc_key`)
- Último erro de parse da IA (`ai_last_parse_error` — JSON com `log`, `type`, `message`, `timestamp`)

### mod_amssoft_fail2ban_ai_suggestions
Sugestões da IA com status (pending/approved/rejected/auto_executed). Inclui campos v3: `filter_name`, `failregex`, `filter_created_at`. **v9:** `source_log` — path do log de origem (elimina inferência por keywords para logpath de filtros auto-criados). **Agrupamento por país:** `getPendingGroupedByCountry()` faz JOIN com `geo_cache` para agrupar pendentes por `country_code`. `getPendingIdsByCountry($cc)` retorna IDs pendentes de um país específico (vazio = sem geo data). Usado para ações em massa (bulk approve/reject) na UI. **Seleção cross-page:** cards de país com botão "Selecionar" que busca todos os IDs via AJAX, armazena em sessionStorage, e permite ação em massa com checkboxes + barra fixa. **Comportamento de IPs rejeitados:** `rejected` é intencionalmente excluído da dedup (`getKnownIPs` e `saveSuggestion` verificam apenas `pending/approved/auto_executed`). Se o admin rejeitar um IP e ele continuar atacando, a IA pode detectá-lo novamente e criar nova sugestão. Decisão de design: rejeitar não é permanente — o IP pode voltar se houver nova evidência.

### mod_amssoft_fail2ban_geo_cache
Cache de dados geográficos de IPs (via ip-api.com). PRIMARY KEY em `ip`, com `updated_at` para TTL (30 dias). Campos: `country` (nome por extenso), `country_code` (ISO 3166-1 alpha-2, ex: "BR"), `region`, `isp`, `asn` (apenas o número, ex: "AS28573" — extraído do campo `as` da API). Chaves na tabela config: `geoip_requests_this_minute`, `geoip_minute_window_start`, `geoip_cooldown_until` (rate limiting global).

### Migrações
- **v2** (`amssoft_fail2ban_migrate_v2`): cria tabela ai_suggestions se não existir
- **v3** (`amssoft_fail2ban_migrate_v3`): adiciona colunas filter_name, failregex, filter_created_at
- **v4** (`amssoft_fail2ban_migrate_v4`): multi-provider IA — migra chaves antigas para formato por provedor, garante `ai_active_provider`
- **v5** (`amssoft_fail2ban_migrate_v5`): cria tabela geo_cache para dados geográficos de IPs
- **v6** (`amssoft_fail2ban_migrate_v6`): limpa chave legada `ai_provider_mimo_protocol` (protocolo fixo OpenAI)
- **v7** (`amssoft_fail2ban_migrate_v7`): expande ENUM da coluna `action` para incluir `analysis_locked` e ações de auto-criação (`jail_created`, `auto_filter_fallback`, `auto_filter_error`, `auto_filter_dedup`, `auto_filter_orphan`, `auto_filter_orphan_cleanup_failed`)
- **v8** (`amssoft_fail2ban_migrate_v8`): expande ENUM com `lock_config_warning`. Garante `data/locks/` com setgid e `data/.htaccess` com Deny from all. Campo `web_process_group` na config.
- **v9** (`amssoft_fail2ban_migrate_v9`): adiciona coluna `source_log` em `ai_suggestions` — propaga path do log de origem para cada sugestão, eliminando inferência por keywords.

Todas são idempotentes e executadas automaticamente em cada carregamento do módulo (`amssoft_fail2ban_output`).

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

**Jail `ai-bans`:** criada automaticamente durante `activate()` se não existir. Usa filtro `apache-auth` como placeholder (maxretry=5, findtime=600, bantime=3600). É o jail padrão para bans feitos pela IA quando a sugestão não especifica um jail.

### FilterManager
Cria filtros fail2ban em `/etc/fail2ban/filter.d/`:
- Nome: prefixo `amsfb-`, sanitizado para `[a-z0-9-]`, max 50 chars
- Validação de failregex: cada linha testada com `preg_match()`, rejeita múltiplos `<HOST>` por linha
- Escrita via temp file + `sudo cp` (fallback se diretório não for gravável)
- Verificação tripla de jail existente: jail.local + jail.d/ + daemon em memória
- **Deduplicação por similaridade:** `findSimilarFilter($failregex)` normaliza failregex (remove `<HOST>`, escapes, delimitadores), extrai tokens, calcula similaridade Jaccard. `tokenizeFailregex()` faz a normalização. Retorna `['name' => ..., 'similarity' => ..., 'failregex' => ...]`.
  - **Threshold de similaridade (trade-off):**
    - Fluxo manual (botão "Criar Filtro"): 50% — admin revisa e decide
    - Fluxo automático (auto/threshold via `autoCreateFilterAndBan`): 65% — sem humano, exige mais certeza
    - Impacto: no modo auto, padrões com similaridade entre50-65% criam filtros separados em vez de reusar existentes. Pode gerar mais filtros no disco, mas evita falsos positivos na dedup.
    - Os thresholds são fixos no código (não configuráveis via UI). Ajustar em `AutoBanEngine.php` (auto) e `AIController.php` (manual).
- **TOCTOU fix:** `createJailForFilter()` re-verifica `jailExists()` após `addJail()` falhar — corrige corrida onde dois processos veem "não existe" simultaneamente.
- **Detecção segura de logpath:** `detectLogPathSafe($failregex, array|string $evidenceJson, $filterName)` valida contra allowlist fixa de 7 logs. Aceita evidence como string JSON ou array já decodificado (normaliza internamente). Se o logpath inferido não estiver na allowlist, tenta fallback para `whmcs_auth.log` (apenas se `attackMatchesLog()` confirmar compatibilidade do tipo de ataque com o log). Retorna `null` se nenhum log seguro for encontrado (caller cai para `ai-bans`).
- **Allowlist de logs:** `/var/log/whmcs_auth.log`, `/var/log/apache2/{error,access,error_whmcs,access_whmcs}.log`, `/var/log/auth.log`, `/var/log/fail2ban.log`
- **Remoção de filtro:** `removeFilter($name)` — remove arquivo `.conf` de filter.d/. Idempotente. Usado para limpar filtros órfãos (filtro criado mas jail falhou).

### Sudoers
Arquivo `setup/sudoers/amssoft_fail2ban` concede NOPASSWD para:
- `fail2ban-client` (status, set banip/unbanip, reload, ping)
- `/bin/cp /tmp/amsfb_filter_* /etc/fail2ban/filter.d/amsfb-*` (criação de filtros pela IA)
- `/bin/chmod 644 /etc/fail2ban/filter.d/amsfb-*`
- `Defaults:www-data !requiretty`

### LogViewer
Leitura e análise de arquivos de log. Validação de path via `isValidPath()` (SEC-8: restringe a `/var/log/`, `/var/www/html/`, `/tmp/`).

**Métodos de leitura:**
- **`readLines($path, $lines)`** — lê as últimas N linhas do arquivo (usado pelo Log Viewer e pelo `force=1`). Cap: 1000 linhas.
- **`readNewLinesFromOffset($path, $offset, $maxLines)`** — lê linhas novas a partir de um offset. Retorna `['lines' => array, 'offset' => int]` onde `offset` é o byte real onde a leitura parou (via `ftell()`). Cap: 1000 linhas. O watermark é atualizado para `offset` (não para `filesize`) — evita pular linhas quando o log tem mais conteúdo que o limite.

**Descoberta e análise:**
- **`getAvailableLogs($extra)`** — varre logs bem conhecidos (`WELL_KNOWN_LOGS`), custom logs do DB (`custom_log.*`), logpaths de jails (`logpath.*`), e `fail2ban.log`
- **`filterLinesByIPs($lines, $skipIPs)`** — estático, remove linhas cujos IPs estão todos na lista de skip. Mantém linhas sem IP e linhas com pelo menos 1 IP relevante. Usado como pre-filter antes de enviar à IA (economiza tokens).
- **`extractIPs($lines)`** — extrai IPv4/IPv6 de linhas de log
- **`highlightSuspicious($lines)`** — marca linhas com classes CSS (normal/suspicious/error)
- **`isValidPath($path)`** — validação de path (SEC-8)

## Integração com IA (Multi-Provider)

### AIAnalyzer — Registry de Provedores

Arquitetura multi-provider com dispatch por **protocolo** (não por nome). Cada provedor define protocolo, modelos, e se a URL é editável.

```php
AIAnalyzer::PROVIDERS = [
    'anthropic' => [
        'protocol'   => 'anthropic',
        'models'     => ['claude-haiku-4-5-20251001', 'claude-sonnet-4-6', 'claude-opus-4-6'],
        'max_tokens' => 8192,  // Claude suporta até 8192 tokens de output
        ...
    ],
    'mimo' => [
        'protocol'         => 'openai',      // fixo — Anthropic removido (deep thinking consumia todos os tokens)
        'disable_thinking' => true,          // desativar deep thinking do MiMo
        'models'           => ['mimo-v2.5-pro', 'mimo-v2.5'],
        'max_tokens'       => 4096,          // MiMo: manter 4096 até confirmar suporte a 8192
        ...
    ],
];
```

Adicionar provedor futuro = 1 entrada no array `PROVIDERS`.

**Provedores suportados:**
- **Anthropic (Claude)** — protocolo próprio, endpoint `https://api.anthropic.com/v1/messages`
- **MiMo (Xiaomi)** — protocolo fixo OpenAI, endpoint `https://token-plan-sgp.xiaomimimo.com/v1/chat/completions`
  - Deep thinking desativado via `"thinking": {"type": "disabled"}` no body (evita consumo excessivo de tokens)
  - Protocolo Anthropic removido: o deep thinking do MiMo consome todos os tokens de `max_completion_tokens` sem gerar resposta útil, causando timeout

**Migração v6:** limpa chave legada `ai_provider_mimo_protocol` do banco (protocolo agora é fixo no registry).

**Configuração no banco (chaves dinâmicas por provedor):**
- `ai_active_provider` — provedor ativo (`anthropic` | `mimo`)
- `ai_provider_{name}_api_key` — chave API criptografada (AES-256-CBC)
- `ai_provider_{name}_model` — modelo selecionado
- `ai_provider_{name}_base_url` — endpoint (apenas para provedores com `needs_base_url`)
- `ai_provider_{name}_last_ping` — último ping OK

**Migração v4 (multi-provider):**
- Chaves antigas `ai_api_key` e `ai_model` são migradas automaticamente para `ai_provider_anthropic_*`
- Migração preserva valor já criptografado (copia direto, sem decriptar/recriptografar)
- Guard idempotente: só migra se a chave antiga existir E a nova estiver vazia
- Base URLs salvas para provedores com `needs_base_url=false` são limpas automaticamente
- Executada em `amssoft_fail2ban_output()` (padrão v2/v3), não no controller

**Criptografia de API keys (todos os provedores):**
- Todas as chaves usam `Helper::encryptApiKey()` → AES-256-CBC com mesma `_enc_key`
- Chave nunca é decriptada e exibida na UI (campo mascarado `●●●●●●●●`)
- `showSettings()` só verifica se a chave existe (boolean `api_key_set`), não o valor
- `persistSettings()` só salva se o campo não estiver vazio (mantém a existente)

**Configurações compartilhadas entre provedores:**
- Prompt (`ai_prompt`) — mesmo prompt para todos os provedores
- Modo de operação, intervalo, confiança mínima, whitelist, thresholds

- Logs truncados em N linhas (configurável: 200/400/600/800/1000)
- Prompt customizável pelo admin (max 8000 chars). **DEFAULT_PROMPT** (`AIAnalyzer::getDefaultPrompt()`) inclui contexto WHMCS: webhooks de pagamento (Mercado Pago), crawlers legítimos (facebookexternalhit, ChatGPT-User, LinkPreviewBot), comportamento normal de clientes. Se o admin nunca salvou prompt customizado, o default é usado.
- **Cap de ameaças:** `buildPrompt()` injeta "Retorne no máximo 10 ameaças, priorizando as de maior severidade e confiança" no system prompt — aplica-se a TODOS os prompts (default e customizado do admin). Garante que a resposta cabe dentro do budget de `max_tokens` mesmo com logs densos.
- **Detecção de truncamento:** `callApi()` verifica `stop_reason`/`finish_reason` da resposta. Se for `"max_tokens"` ou `"length"`, lança `TruncatedResponseException` — o controller captura e sinaliza ao frontend via flag `truncated`. Watermark NÃO avança (log será reanalisado).
- **Detecção de JSON inválido:** `parseResponse()` lança `InvalidResponseException` se a resposta não for JSON array válido. Controller captura, sinaliza via `parse_failed`, e registra em `ai_last_parse_error` no banco. Watermark NÃO avança.
- **Mitigação de prompt injection (SEC-16):** 3 camadas: (1) delimitador aleatório por requisição (`<log_data_{token}>`), (2) instruções no system prompt para ignorar conteúdo dentro das tags, (3) heurística de fallback regex quando IA retorna `[]` para linhas com padrões suspeitos. **Diferença entre provedores:** MiMo tem ~30% de resistência a payload de fechamento de tag (fraqueza do modelo); Anthropic tem ~100%. A heurística de fallback é defesa primária para MiMo, defense-in-depth para Anthropic.

### LogLock — Lock cross-user (cron ↔ painel)

Lock de arquivo compartilhado entre cron (root) e painel web (www-data).
Resolve o bug onde lock files em `/tmp/` criados por root (644) não podiam
ser abertos por www-data, causando falso "analysis_locked".

**Diretório:** `data/locks/` (dentro do projeto, não `/tmp/` nem `/var/lock/`).
- `data/.htaccess` — `Deny from all` (bloqueia acesso HTTP)
- `data/locks/` — `2770 www-data:www-data` (setgid: lock files herdam grupo)
- Lock files: `root:www-data 660` (setgid herda grupo do diretório)
- **NÃO é necessário `chown root:www-data`** — setgid funciona com `www-data:www-data`

**Métodos:**
- `LogLock::acquire($logPath)` — retorna `['fp' => resource|null, 'reason' => string|null]`
  - `reason`: `'fopen_failed'` (permissão) ou `'locked_by_other'` (concorrência real)
- `LogLock::release($fp)` — libera lock (trata null graciosamente)
- `detectWebGroup()` — detecta grupo do processo web em runtime

**Modo degradado:** se o grupo do `data/locks/` for `root` (configuração incorreta),
`acquire()` retorna `fopen_failed`. AutoBanEngine entra em modo degradado: análise
continua SEM lock, `lock_config_warning` é logado. Não bloqueia a IA.

**Hospedagem compartilhada:** se o cron roda como o mesmo usuário do site
(não-root), o lock funciona sem setgid — mesmo usuário cria e lê o arquivo.

### AutoBanEngine — 3 modos
1. **suggestion** — IA sugere, admin aprova manualmente
2. **auto** — IA analisa e bane imediatamente (requer confirmação explícita do admin)
3. **threshold** — IA aguarda N detecções em X minutos por severidade

**`runAnalysis($forceReread)`:**
- `false` (cron automático): usa watermark, pula logs sem conteúdo novo, pula IPs banidos + pendentes
- `true` (manual via `run_now`): ignora watermark e relê as últimas N linhas, mas NÃO atualiza o watermark (para não perder bytes novos). Pula apenas IPs banidos ativos.
- Método privado `readNewLines()` delega para `LogViewer::readNewLinesFromOffset()` — lógica centralizada em um único lugar.

**Métodos compartilhados (usados pelo cron e pelo controller):**
- `filterSuggestions($raw, $skipIPs)` — estático, filtra sugestões cruas da IA (whitelist, dedup, confiança mínima, ação=ban)
- `loadWhitelist()` — estático, carrega whitelist de IPs do banco
- `processSuggestion($suggestion, $mode)` — processa uma sugestão de acordo com o modo (salva, bane se auto/threshold). Retorna `['id', 'status', 'banned', 'threshold_reached']`. Usado por `runAnalysis()` (cron) e disponível para o controller.
- `heuristicFallback($lines)` — fallback regex quando IA retorna `[]` para linhas com padrões suspeitos. 15 padrões + detecção de UA >500 chars. Confidence 80. Intencionalmente "burra" (regex, não IA) — resistente a prompt injection. Usada como defesa primária para MiMo, defense-in-depth para Anthropic.

**Threshold — contagem de detecções:**
- `countRecentDetections()` conta apenas status `pending` + `auto_executed`
- `rejected` é excluído intencionalmente: se o admin rejeitou, a detecção não vale para o threshold
- Impacto: um atacante cujas sugestões são sempre rejeitadas pelo admin nunca atinge o threshold
- Comportamento esperado: rejeitar = "não é ameaça real", não deve contar para automação

### Auto-criação de filtro/jail (gate por ocorrências)

Quando `ai_auto_create_filter=1`, o `executeBan()` pode criar filtro/jail específico automaticamente. O gate não depende do `ai_mode` — usa contagem de ocorrências do padrão.

**Gate duplo:**
- `occurrences >= ai_auto_create_min_occurrences` (default: 3, configurável na UI)
- `distinct_ips >= ai_auto_create_min_distinct_ips` (default: 2, configurável na UI — exige IPs diferentes para provar generalização)
- Janela de tempo: `ai_auto_create_window_days` (default: 30 dias, configurável na UI)
- Exclui status `rejected` (decisão explícita do admin não conta a favor)

**Fluxo:**
```
IA detecta ameaça com filter_name="apache-scan"
    → salva sugestão (sempre)
    → bane IP (sempre, seguindo ai_mode)
    → se ai_auto_create_filter=1:
        → conta ocorrências de "apache-scan" (excluindo rejected)
        → se occurrences >= 3 E distinct_ips >= 2:
            → filtro já existe por nome? → bane na jail do filtro
            → filtro não existe:
                → findSimilarFilter() — filtro similar por failregex (≥65%)?
                    → sim: reusa filtro existente, loga auto_filter_dedup
                    → não: cria filtro + jail → bane lá
        → se gate não atingido: bane em ai-bans (aguarda mais ocorrências)
```

**Métodos:**
- `Database::analyzeFilterNameOccurrences($filterName, $windowDays)` — retorna `occurrences`, `distinct_ips`, `best_failregex`, `all_failregex` (top 5), `best_source_log`
- `Database::incrementConfig($key)` — UPDATE atômico `value = value + 1` (corrige TOCTOU no contador)
- `AutoBanEngine::autoCreateFilterAndBan($suggestion, $adminId)` — cria filtro+jail via FilterManager, bane na jail específica. Retorna `null` em caso de falha (fallback para ai-bans). Dedup por similaridade (threshold 0.65) antes de criar filtro.
- `FilterManager::detectLogPathSafe($failregex, array|string $evidence, $filterName)` — fallback para sugestões sem `source_log`. Prioridade: `source_log` propagado do pipeline (dado real) > `detectLogPathSafe()` (inferência por keywords). `getAllowedLogs()` retorna a allowlist de logs permitidos.

**Segurança:**
- Allowlist de logs: `/var/log/whmcs_auth.log`, `/var/log/apache2/{error,access,error_whmcs,access_whmcs}.log`, `/var/log/auth.log`, `/var/log/fail2ban.log`
- Limite diário: `ai_auto_max_jails_per_day` (default: 5)
- **Lock por filter_name:** `flock(LOCK_EX)` em arquivo `/tmp/amsfb_lock_{md5(filterName)}` antes de criar filtro/jail. Garante que apenas uma processo cria; a outra encontra o filtro/jail já existente. Lock liberado em `finally`.
- TOCTOU em `createJailForFilter()`: re-check `jailExists()` após `addJail()` falhar
- Log via `logEvent()` (INSERT, não sobrescreve): `jail_created`, `auto_filter_fallback`, `auto_filter_error`, `auto_filter_dedup`, `auto_filter_orphan`, `auto_filter_orphan_cleanup_failed`, `lock_config_warning`

**Dashboard:** badge "N jail(s) auto-criado(s) hoje" com lista dos últimos eventos.

### Deduplicação (3 camadas)
1. **Whitelist pre-filter:** remove linhas cujos IPs são todos whitelisted/banidos/pendentes **antes** de enviar à IA. Economiza tokens — linhas com IPs irrelevantes nunca chegam à API. Implementado em `LogViewer::filterLinesByIPs()`, chamado por `AIController::ajaxAnalyzeLog()` e `AutoBanEngine::runAnalysis()`. Mantém linhas sem IP (podem ter padrões de ataque) e linhas com IPs mistos (whitelisted + não-whitelisted).
2. **Watermark por arquivo:** lê apenas bytes novos desde última análise (offset no banco)
3. **IP dedup (pós-IA):** `filterSuggestions()` remove sugestões para IPs já banidos/pendentes/whitelisted — safety net após a resposta da IA

**Comportamento do watermark (resumo — detalhes nos comentários inline do código):**
- Chave `ai_log_offset.{md5(path)}`, compartilhada entre cron e controller (decisão de design).
- Usa `ftell()` (offset real lido), não `filesize()` — evita pular linhas quando log excede `ai_log_lines`.
- Só avança após sucesso (API + parse + save). `force=1` não atualiza watermark.
- Rolling TTL: sessão renova a cada `analyze_log` OK; expira 5min sem progresso.
- Skip client-side: `has_new` em `list_logs` compara `filesize > watermark` (otimização, não gate).
- `is_readable()` check antes de processar — watermark não reseta se arquivo ilegível.
- Lock por log: `flock(LOCK_EX | LOCK_NB)` em `/tmp/amsfb_log_{md5(realpath(path))}.lock` previne que cron e manual processem o mesmo arquivo simultaneamente. Ver seção "Lock de concorrência" abaixo.
- Pre-filter vazio: watermark avança mesmo assim (evita reprocessar infinitamente).

### Lock de concorrência (cron vs. manual)

Quando o cron automático e o admin clicam "Analisar agora" ao mesmo tempo, o lock por log previne processamento duplicado do mesmo arquivo.

**Mecanismo:**
- Lock file: `/tmp/amsfb_log_{md5(realpath(path))}.lock`
- Tipo: `flock(LOCK_EX | LOCK_NB)` — exclusivo, não-bloqueante
- Normalização: `realpath()` canonicaliza o path antes do hash (evita mismatch com symlinks ou `//`)
- Liberação: `finally` garante unlock mesmo em exceção
- Se o lock não é adquirido: retorna `analysis_running` (manual) ou `skipped_locked` (cron)
- `is_readable()` é verificado **antes** do lock — evita criar lock files em `/tmp` para logs inexistentes

**Lógica do `$allLocked` (distinção entre "bloqueado" e "nada pra fazer"):**
- `$allLocked` inicia `true`
- Muda para `false` quando um lock é **adquirido com sucesso** (independente de ter conteúdo novo, pre-filter, etc.)
- Permanece `true` apenas quando **nenhum** lock foi adquirido (todos bloqueados por outros processos)
- Logs não-legíveis são pulados antes do lock — não afetam `$allLocked`
- Logs sem conteúdo novo (watermark = filesize) fazem lock, setam `$allLocked = false`, e fazem `continue`

**`runAnalysis()` — retorno com metadados:**
- `[]` — nenhum log disponível (normal, `ai_last_run` é atualizado)
- `['_locked_out' => true]` — havia logs mas nenhum lock foi adquirido (`ai_last_run` NÃO é atualizado — próximo cron tenta em 4min)
- `[{...}]` — resultados normais (`ai_last_run` é atualizado)

**hooks.php:** só atualiza `ai_last_run` quando `!isset($result['_locked_out'])`. Se todos os logs estavam bloqueados, o próximo tick do WHMCS (4 min) tenta novamente em vez de esperar `ai_interval_minutes` (default 30 min).

**Observabilidade:** eventos `analysis_locked` são registrados via `Database::logEvent()` — permite confirmar em produção que o mecanismo está funcionando. Consultar: `SELECT * FROM mod_amssoft_fail2ban_logs WHERE action='analysis_locked' ORDER BY timestamp DESC`.

### Permissões de arquivos de log

O módulo lê logs de vários diretórios. O processo web (www-data) precisa ter permissão de **leitura** nos arquivos de log. Permissões aplicadas no servidor:

```
root:www-data 640 /var/log/apache2/access_whmcs.log
root:www-data 640 /var/log/fail2ban.log
root:www-data 640 /var/log/apache2/access.log
root:www-data 640 /var/log/apache2/error.log
```

Logs que já eram legíveis por www-data:
```
www-data:www-data 640 /var/log/whmcs_auth.log
root:www-data 640 /var/log/auth.log
root:www-data 640 /var/log/apache2/error_whmcs.log
```

**Se novos logs forem adicionados** e o "Analisar agora" não conseguir lê-los, o módulo retornará "Arquivo não legível pelo servidor web" — não resetará o watermark.

### Logrotate e permissões (corrigido em 2026-07-02)

**Problema:** O logrotate do Apache2 (`/etc/logrotate.d/apache2`) usa `create 640 root adm` — novos arquivos após rotação ficam com grupo `adm`. Como `www-data` não pertence ao grupo `adm`, perde acesso de leitura. Resultado: logs mostram "⚠ Sem permissão" no `action=logpaths` após rotação.

**Correção aplicada:** Comando `chown root:www-data` + `chmod 640` no `postrotate` do logrotate:
```
postrotate
    ...reload apache2...
    # Garante que www-data pode ler logs usados pelo módulo Fail2Ban WHMCS
    chown root:www-data /var/log/apache2/access_whmcs.log /var/log/apache2/error_whmcs.log /var/log/apache2/access.log /var/log/apache2/error.log 2>/dev/null
    chmod 640 /var/log/apache2/access_whmcs.log /var/log/apache2/error_whmcs.log /var/log/apache2/access.log /var/log/apache2/error.log 2>/dev/null
endscript
```

**Backup:** `/etc/logrotate.d/apache2.bakp.*`

**Verificação:**
```bash
# Testar se logrotate mantém permissões após rotação forçada
logrotate -f /etc/logrotate.d/apache2
ls -la /var/log/apache2/*.log

# Testar leitura como www-data
sudo -u www-data test -r /var/log/apache2/access.log && echo OK || echo FAIL
```

**Nota:** O `create 640 root adm` no logrotate NÃO foi alterado (seria invasivo demais para todos os logs Apache). A correção é seletiva: apenas os 4 logs usados pelo módulo recebem `chown` no postrotate.

### TruncatedResponseException / InvalidResponseException
Exceções em `lib/TruncatedResponseException.php` e `lib/InvalidResponseException.php`:
- **TruncatedResponseException** — lançada por `AIAnalyzer::callApi()` quando `stop_reason: "max_tokens"` (Anthropic) ou `finish_reason: "length"` (OpenAI). Resposta cortada por atingir limite de tokens.
- **InvalidResponseException** — lançada por `AIAnalyzer::parseResponse()` quando a resposta da IA não contém JSON válido (texto livre, erro interno, etc.).

O controller captura ambas e: (1) NÃO avança watermark (log será reanalisado), (2) NÃO renova TTL da sessão, (3) sinaliza ao frontend via flags `parse_failed`/`truncated`, (4) registra detalhes em `ai_last_parse_error` no banco (config KV).

### Criação de filtros pela IA
- **Cenário A:** sugestão já tem failregex → cria filtro diretamente
- **Cenário B:** sem failregex mas com evidence → chama IA para gerar on-demand
- Filtro criado em `/etc/fail2ban/filter.d/amsfb-<nome>.conf`
- Jail criada em `jail.local` com nome `amsfb-<nome>`

### Criptografia da API Key
- AES-256-CBC com IV aleatório
- Chave de criptografia: 32 bytes aleatórios persistidos no banco (`_enc_key`)
- Formato: `base64(iv + ciphertext)`

## Integração GeoIP (ip-api.com)

Lookup de dados geográficos de IPs via API pública ip-api.com (sem chave, sem instalação). Endpoint: `http://ip-api.com/json/{ip}`. Rate limit: 45 req/min, timeout 3s.

**Classe `lib/GeoIP.php`** — métodos principais: `lookup()`, `bulkLookup()` (cache-first), `isAvailable()`, `getStatus()`, `clearCache()`, `countryToFlag()`, `formatGeo()`.

**Rate limiting (3 camadas):**
1. Global: contador no DB (safety limit: 40/min)
2. Batch limit: `min(remaining, 10)` por carregamento de página
3. Cooldown 429: persiste `geoip_cooldown_until` no banco (60s)

**Cache:** tabela `mod_amssoft_fail2ban_geo_cache`, TTL 30 dias, upsert batch. IPs privados/reserved não fazem request HTTP.

**Configuração:** seção "GeoIP" em ai_settings.tpl — botões "Testar conexão" e "Limpar cache geo".

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
| ips | IpsController | Página + AJAX |
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
- Validadas com CSRF token (rotacionado após cada uso, exceto `fetch_lines` — ver SEC-7)
- Respondem com JSON

### Jails (action=jails)
- `do=enable` — habilita jail
- `do=disable` — desabilita jail
- `do=remove` — remove jail
- `do=reload_all` — reload geral do fail2ban

### IPs (action=ips)
- `do=unban` — desbane IP via AJAX. POST: `ip`, `jail`. Retorna `success`, `message` ou `error`. Inclui fallback: se `unbanIP()` falhar, verifica se o IP já não está banido.
- `do=ban` — bane IP via AJAX. POST: `ip`, `jail`. Retorna `success`, `message` ou `error`.

### IA (action=ai)
- `do=approve` — aprova sugestão (bane IP via provedor ativo)
- `do=reject` — rejeita sugestão
- `do=run_now` — executa análise manual em lote via provedor ativo (legado, usado em ai_settings). Respeita `ai_mode`: modo auto → bane imediatamente; modo suggestion → salva pending. Chama `AutoBanEngine::runAnalysis(true)`.
- `do=list_logs` — lista logs disponíveis para análise (rate limit: 60s, inicia sessão de análise). Retorna metadata enriquecida por log: `filesize`, `watermark`, `has_new` (boolean). JS usa `has_new` para pular logs sem conteúdo novo sem request ao servidor. Retorna também `ai_mode` (usado pelo frontend para avisos).
- `do=analyze_log` — analisa um único log (requer sessão ativa, usa watermark, retorna sugestões salvas). Aceita `force=1` no POST para ignorar watermark e reanalisar (útil após trocar prompt/modelo). Campos extras no JSON de resposta: `parse_failed` (boolean), `truncated` (boolean — resposta cortada por max_tokens). Em caso de 429 do provedor, retorna `{success: false, error: 'rate_limited', retry_after: 60}`. **Sempre salva como `pending` independente do `ai_mode`** (ferramenta de revisão — bans automáticos ocorrem via cron).
- `do=ping_api` — testa conexão com API (aceita `provider` no POST)
- `do=save_settings` — salva configurações (multi-provider: provedor ativo, chave, modelo)
- `do=create_filter` — cria filtro fail2ban a partir de sugestão (usa provedor ativo)
- `do=bulk_approve_ids` — aprova sugestões por lista de IDs. POST: `ids` (JSON array de ints positivos, max 200). Best-effort: IDs com `status != 'pending'` são ignorados silenciosamente. Retorna `approved_ids`, `failed_ids`, `dismissed_ids`.
- `do=bulk_reject_ids` — rejeita sugestões por lista de IDs. POST: `ids` (JSON array de ints positivos, max 200). Batch UPDATE com `WHERE status = 'pending'`. Retorna `rejected` (count), `rejected_ids` (array).
- `do=get_ids_by_country` — retorna todos os IDs pendentes de um país. POST: `country_code` (ISO 3166-1 alpha-2 ou vazio para "Desconhecido"). Usado pela seleção cross-page (ver seção "Seleção cross-page" abaixo).

**Fluxo "Analisar agora" (sequencial com progresso):**
1. JS chama `do=list_logs` → retorna todos os logs disponíveis com metadata (`filesize`, `watermark`, `has_new`)
2. Para cada log: JS verifica `has_new` client-side — se false, pula sem request ao servidor
3. JS chama `do=analyze_log` com path → analisa, salva sugestões, retorna
4. Linhas são adicionadas dinamicamente na tabela com 5 botões de ação
5. Delay adaptativo entre requests: 500ms base, backoff automático em 429 do provedor
6. Rolling TTL: sessão renova a cada `analyze_log` bem-sucedido (não expira enquanto houver progresso)
7. Resumo final discrimina: analisados, pulados, falhados (com paths), truncados + mensagem de retry explícita

**Rate limiting (SEC-10):**
- `do=list_logs`: 60s entre sessões (protege contra abuso)
- `do=analyze_log`: sem rate limit individual (progresso sequencial rápido), mas requer sessão ativa
- `do=run_now`: 60s (legado, mantido para ai_settings)
- **Delay adaptativo (JS):** 500ms entre requests. Em 429, respeita `retry_after` do servidor (não limitado por MAX_DELAY) + countdown visual no botão ("Rate limit — aguardando 58s...")
- **Detecção de 429:** `AIAnalyzer::getLastHttpCode()` retorna o HTTP code da última chamada. Controller detecta 429 e retorna `{error: 'rate_limited', retry_after: 60}` ao JS

**Seleção cross-page ("Ações por País"):**
- Cards de país acima da tabela pendente mostram bandeira, nome e contagem de IPs
- Botão "Selecionar" busca TODOS os IDs pendentes do país via `do=get_ids_by_country` (AJAX)
- IDs armazenados em objeto `selectionByCountry` no JS (persistido em `sessionStorage`)
- Checkboxes visíveis na página são marcados como reflexo parcial do estado real
- IDs de outras páginas ficam "virtualmente" selecionados (sobrevivem reload da paginação)
- Ao desmarcar checkbox individual, ID é removido do `selectionByCountry`
- "Selecionar todos desta página" (`#amsfb-select-all`) marca/desmarca apenas visíveis; ao desmarcar, remove do `selectionByCountry` apenas IDs visíveis (preserva cross-page)
- Barra de ação fixa (`position: fixed; bottom: 0`) mostra contagem total + breakdown visíveis/outras páginas
- "Banir/Rejeitar Selecionados" envia `getSelectionIds()` (merge de cross-page + checkboxes visíveis)
- Após ação, IDs processados são removidos do `selectionByCountry` e do `sessionStorage`
- Toggle: clicar "Selecionar" novamente desmarca todos os IPs daquele país

### GeoIP (action=ai)
- `do=ping_geoip` — testa conectividade com ip-api.com (usa IP fixo 8.8.8.8)
- `do=clear_geoip_cache` — trunca tabela geo_cache

### Log Viewer (action=logviewer)
- `do=fetch_lines` — lê linhas do log (retorna `geo_data` com lookup dos IPs mais frequentes, máx 20). **Não rotaciona CSRF token** (read-only, auto-refresh a cada 5s).
- `do=ban_ip` — bane IP inline
- `do=analyze` — analisa log com IA. **Retry automático** em falha CSRF (edge case: token rotacionado por outro AJAX concorrente).

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
- **[SEC-7]** Rotação de CSRF token após cada uso (exceção: `fetch_lines` não rotaciona — read-only, auto-refresh a cada 5s, evita race condition com AJAX concorrentes)
- **[SEC-8]** Restrição de paths do LogViewer a `/var/log/`, `/var/www/html/`, `/tmp/`
- **[SEC-9]** Flag de confirmação para modo automático da IA
- **[SEC-10]** Rate limiting: 60s em `list_logs` (início de sessão), sessão de análise expira em 300s, `analyze_log` requer sessão ativa
- **[SEC-11]** Limite de 8000 chars no prompt customizado
- **[SEC-12]** CSRF validado incondicionalmente em todas as requisições AJAX POST
- **[SEC-13]** *(reservado — não implementado)*
- **[SEC-14]** Evitar `Capsule::raw()` com variável interpolada
- **[SEC-15]** Validação de status contra ENUM antes de UPDATE
- **[SEC-16]** Mitigação de prompt injection (system prompt + tags `<log_data>` + delimitador aleatório por requisição + heurística de fallback regex). **Importante:** MiMo tem ~30% de resistência a payload de fechamento de tag; Anthropic tem ~100%. A heurística de fallback (`AutoBanEngine::heuristicFallback()`) é defesa primária para MiMo, defense-in-depth para Anthropic. NUNCA desativar a heurística sem considerar o provedor ativo.
- **[SEC-17]** Base URL editável: validação https:// + bloqueio de IPs privados/localhost/link-local 169.254.x.x (SSRF defense)
- **[SEC-18]** `ai_active_provider` validado contra registry antes de persistir
- **[SEC-19]** Erros de API: mensagem genérica no frontend, detalhes nunca expostos
- **[SEC-20]** Validação de IDs em bulk actions: JSON array de ints positivos, max 200, verificação de `status = 'pending'` antes de processar. Validação de `country_code` em `get_ids_by_country`: regex `/^[A-Z]{2}$/` ou vazio.

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
| "Arquivo não legível pelo servidor web" (not_readable) | Logs `root:adm 640` não são legíveis por www-data. Corrigir: `chown root:www-data /var/log/apache2/access_whmcs.log /var/log/fail2ban.log` (e outros logs necessários). Ver seção "Permissões de arquivos de log". |
| Logs perdem permissão após rotação (logrotate) | Logrotate do Apache usa `create 640 root adm` — novos arquivos ficam sem acesso para www-data. Corrigido: `chown root:www-data` no `postrotate` de `/etc/logrotate.d/apache2`. Ver seção "Logrotate e permissões". |
| Lock files com permissão errada → falso "analysis_locked" | Lock files em `/tmp/amsfb_log_*.lock` criados por root (644) não podiam ser abertos por www-data. Corrigido: `LogLock.php` usa `data/locks/` com setgid (2770). Ver seção "LogLock". |
| TypeError em `detectLogPathSafe()` com evidence como array | `detectLogPathSafe()` recebia `array` de `AutoBanEngine` mas esperava `string`. Corrigido: assinatura `array\|string` com normalização no topo. Ver CHANGELOG. |
| **VS Code Remote-SSH não conecta — fail2ban banne localhost (127.0.0.1)** | O jail `ai-bans` em `/etc/fail2ban/jail.local` **não tinha `ignoreip`** configurado. Quando o fail2ban detectava tráfego suspeito de 127.0.0.1 (loopback do Apache/WHMCS), bania o próprio localhost via iptables. Isso bloqueava o VS Code Server que escuta em `127.0.0.1:<porta>` — o tunnel SSH recebia "Connection refused" porque o iptables REJECT impedia conexões locais. **Sintoma:** VS Code conecta via SSH, server inicia, mas port forwarding falha com `channel N: open failed: connect failed: Connection refused`. **Diagnóstico:** `iptables -L f2b-ai-bans -n | grep 127.0.0.1` mostra REJECT. **Correção:** `iptables -D f2b-ai-bans -s 127.0.0.1 -j REJECT` + adicionar `ignoreip = 127.0.0.1` na seção `[ai-bans]` do jail.local (garante que não volte a acontecer). **Importante:** outros jails já tinham `ignoreip = 127.0.0.1` configurado — o `ai-bans` era o único sem, por isso foi o único a banir localhost. |

### Limitações Conhecidas (edge cases aceitos)

| Cenário | Impacto | Mitigação |
|---|---|---|
| **Logrotate copytruncate** — se o analysis rodar no exato momento em que o logrotate zera o arquivo (janela de ~ms), `currentSize < storedOffset` e o offset reseta para 0. O trecho recém-escrito antes da rotação pode ser reanalisado. | Baixo: reprocessamento pontual, sem perda de dados. Sugestões duplicadas são prevenidas pelo upsert por IP. | Nenhuma — edge case tolerável. Se o logrotate rodar a cada 24h, a janela de colisão é ~ms vs 86400s. |
| **Concorrência no watermark** — duas requisições simultâneas (duplo clique, cron + manual) podem ler o mesmo offset e processar o mesmo trecho. | Baixo: 1 chamada API duplicada. Watermark converge; sugestões não duplicam (upsert por IP). | Lock por log (`flock` em `/tmp/amsfb_log_{md5}.lock`) previne processamento simultâneo do mesmo arquivo. Ver seção "Lock de concorrência". |
| **Race condition no rate limit GeoIP** — o estado (`requests_this_minute`, `minute_window_start`, `cooldown_until`) é lido e escrito sem lock. Dois admins simultâneos podem ler o mesmo valor, incrementar, e escrever. | Baixo: pior caso 2-3 requests extras perto do limite de 45. Não causa falha nem perda de dados. | Margem de segurança: safety limit = 40 (não 45). Cooldown de 429 cobre o caso extremo. |
| **Cache geo com ASN antigo** — registros cacheados antes da correção do parsing (que extrai apenas o número ASN) podem ter `asn` com string completa (ex: "AS396982 Google LLC" em vez de "AS396982"). | Baixo: campo `asn` exibido como tooltip/coluna secundária, não afeta funcionalidade. | TTL de 30 dias: registros antigos são substituídos automaticamente. `cleanExpiredGeoCache()` acelera a limpeza se necessário. |
| **`has_new` stale no skip client-side** — `list_logs` calcula `has_new` no momento da requisição. Se o log crescer entre `list_logs` e o `analyze_log` daquele arquivo (possível em logs ativos como Apache), o JS pula mesmo havendo conteúdo novo. | Baixo: conteúdo novo é capturado no próximo ciclo de análise (próximo clique ou cron). | Nenhuma — edge case tolerável. O watermark do servidor é a fonte de verdade; o skip client-side é otimização, não gate. |
| **Reset diário do contador não atômico** — `autoCreateFilterAndBan()` faz read-then-write para resetar `ai_auto_jails_created_today` no início do dia. Duas execuções simultâneas podem ambas resetar, perdendo um incremento. | Baixo: limite diário excedido em 1 jail (de 5). | Nenhuma — cron roda a cada 4 min, colisão improvável. Fix exigiria transação SQL com lock de linha, não trivial no schema KV. |
| **MiMo: evasão via payload de fechamento de tag** — payload `</log_data>` no User-Agent evada detecção em ~70% das tentativas no MiMo (modelo retorna `[]` vazio). Anthropic resiste 100%. Qualquer sintaxe de fechamento de bloco tem a mesma taxa. | Alto para MiMo: ataque real passa despercebido silenciosamente. Baixo para Anthropic. | 3 camadas: delimitador aleatório por requisição + heurística de fallback regex (defesa primária para MiMo) + instruções no system prompt. Ver SEC-16. |

**Observação em produção (2026-06-30):** `whmcs_auth.log` estava com watermark=3884818 mas arquivo=0 bytes — instância real do edge case de rotação. O próximo `analyze_log` resetou o offset para 0 e reanalisou do início (comportamento correto).

> Histórico completo de bugs corrigidos: ver [CHANGELOG.md](CHANGELOG.md). Mudanças significativas são documentadas lá com data, contexto e correção aplicada.

### Padrão de retry CSRF (adotado em todos os endpoints AJAX)

```js
function doAction(_csrfRetried) {
    window.AMSFB.post('action', 'do', params, function (data) {
        if (!data.success && data.error && data.error.indexOf('CSRF') !== -1 && !_csrfRetried) {
            doAction(true); // retry com token atualizado
            return;
        }
        // ... fluxo normal ...
    });
}
doAction(false);
```

**Carregamento de scripts (ordem no layout.tpl):**
1. `$content` (templates com scripts inline) — renderizado primeiro
2. `chart.min.js` — Chart.js
3. `amssoft_fail2ban.js` — define `window.AMSFB.post`
4. Script inline — define `window.AMSFB.moduleLink`, `csrfToken`, etc.

Templates que usam `window.AMSFB` na inicialização (não em handlers de evento) **devem** aguardar `DOMContentLoaded`.

**Importante:** Scripts inline dentro de `$content` são executados **antes** de `amssoft_fail2ban.js` carregar. Para handlers de evento (click, submit), `window.AMSFB.post` estará disponível quando o handler for executado (pois o usuário clica depois do page load). Mas para código que roda imediatamente no IIFE, usar `fetch()` direto em vez de `window.AMSFB.post` — ver `templates/ips.tpl` como exemplo.

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
- **Decodificar HTML entities ao salvar prompts** — templates usam `$e()` (htmlspecialchars). Formulários enviam entidades HTML. `persistSettings()` deve chamar `html_entity_decode()` antes de salvar. Sem isso, cada salvamento double-encode.
- **Watermark só após sucesso** — atualizar offset de watermark SOMENTE depois que a chamada à IA e o salvamento das sugestões tiverem sucesso. Se a API falhar, o watermark não avança e o log será reanalisado.

## Como Adicionar uma Nova Funcionalidade

### Nova página/rota
1. Criar `controllers/XxxController.php` (namespace `AMS\Fail2Ban\Controllers`)
2. Registrar no `CONTROLLER_MAP` em `lib/Router.php`
3. Criar `templates/xxx.tpl` (PHP puro com `extract()` + `ob_start()`)
4. Chamar template via `Router::render('xxx', $data)`

### Novo endpoint AJAX
1. Adicionar método no controller existente (ex: `ajaxMeuEndpoint()`)
2. Adicionar case no `switch` do método `ajax()` do controller
3. No template JS: `window.AMSFB.post('action', 'do', params, callback)`
4. Sempre incluir CSRF retry pattern (ver seção acima)

### Nova tabela no banco
1. Adicionar CREATE TABLE na migração em `amssoft_fail2ban.php` (dentro de `amssoft_fail2ban_activate()` ou nova função de migração)
2. Usar prefixo `mod_amssoft_fail2ban_`
3. Queries via `WHMCS\Database\Capsule` (Eloquent), nunca `Capsule::raw()` com variável interpolada

### Nova configuração
1. Adicionar campo em `amssoft_fail2ban_config()` (array `fields`)
2. Ler via `Helper::getConfig('chave')` ou `Database::getConfig('chave')`
3. Para valores sensíveis: usar `Helper::encryptApiKey()` / `Helper::decryptApiKey()`

## Monitoramento pós-implementação

Checks obrigatórios em cada ciclo de monitoramento consolidado:

### Falsos positivos em filtros multi-pattern
Para cada filtro `amsfb-*` criado com múltiplos failregex (top 5 padrões combinados):
- Verificar amostra dos IPs banidos por ele — algum parece falso positivo?
- A OR de até 5 regex tem superfície de correspondência maior que cada regex isolado
- Confirmar na prática que tráfego legítimo não está sendo capturado

### Gap de detecção — IA vs. logs reais
A IA pode não detectar ameaças que estão registradas nos logs por vários motivos:
- Watermark atrasado (processamento incremental — 200 linhas/run, 15min interval)
- Pre-filter removendo linhas (IPs já banidos/pendentes)
- API rate limit (429 do provedor)
- Falha de parse (resposta truncada, JSON inválido)

**Check obrigatório:** comparar `filesize()` de cada log monitorado com o watermark salvo (`ai_log_offset.<md5>`). Se a diferença for >100KB e crescente entre execuções, ler manualmente uma amostra do conteúdo não processado e avaliar se há tentativas de ataque que a IA não está vendo.

### Gap vs. fail2ban nativo
Comparar timestamp da última sugestão da IA com o último ban do fail2ban (qualquer jail). Se o fail2ban tem bans mais recentes, quantificar o atraso — indica que a IA está processando mais devagar que a detecção nativa.
