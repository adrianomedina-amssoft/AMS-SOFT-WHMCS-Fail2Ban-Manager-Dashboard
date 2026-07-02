# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

**Idioma:** Pense, raciocine e converse sempre em português brasileiro. Todo o raciocínio interno, explicações e comunicação com o usuário devem ser em PT-BR. Código, commits e variáveis permanecem em inglês.

## Visão Geral

Addon WHMCS que gerencia fail2ban via painel admin visual. Elimina a necessidade de SSH/terminal para operações de ban/unban, gerenciamento de jails, visualização de logs e análise de ameaças por IA (multi-provider: Anthropic, MiMo/Xiaomi, e qualquer provedor OpenAI-compatible futuro).

**Status:** Em desenvolvimento (v2.0.0, MIT License)
**Autor:** AMS SOFT — https://www.amssoft.com.br

## Ambiente

- **WHMCS:** 8+ (addon module)
- **PHP:** 8.1+
- **SO:** Debian/Ubuntu (paths hard-coded para Debian)
- **Dependências sistema:** fail2ban, sudo
- **Autoloader:** PSR-4 customizado em `lib/Router.php` (não usa Composer)
- **Templates:** PHP puro (sem Smarty), `extract()` + `ob_start()`

## Working in This Repo

This is a WHMCS addon module — there is no build step, no Composer, no npm. Files are loaded directly by the WHMCS framework.

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

4 tabelas (prefixo `mod_amssoft_fail2ban_`):

### mod_amssoft_fail2ban_logs
Log de eventos (ban/unban/manual_ban/manual_unban). Indexada por ip, jail, timestamp.

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
Sugestões da IA com status (pending/approved/rejected/auto_executed). Inclui campos v3: `filter_name`, `failregex`, `filter_created_at`. **Agrupamento por país:** `getPendingGroupedByCountry()` faz JOIN com `geo_cache` para agrupar pendentes por `country_code`. `getPendingIdsByCountry($cc)` retorna IDs pendentes de um país específico (vazio = sem geo data). Usado para ações em massa (bulk approve/reject) na UI. **Seleção cross-page:** cards de país com botão "Selecionar" que busca todos os IDs via AJAX, armazena em sessionStorage, e permite ação em massa com checkboxes + barra fixa. **Comportamento de IPs rejeitados:** `rejected` é intencionalmente excluído da dedup (`getKnownIPs` e `saveSuggestion` verificam apenas `pending/approved/auto_executed`). Se o admin rejeitar um IP e ele continuar atacando, a IA pode detectá-lo novamente e criar nova sugestão. Decisão de design: rejeitar não é permanente — o IP pode voltar se houver nova evidência.

### mod_amssoft_fail2ban_geo_cache
Cache de dados geográficos de IPs (via ip-api.com). PRIMARY KEY em `ip`, com `updated_at` para TTL (30 dias). Campos: `country` (nome por extenso), `country_code` (ISO 3166-1 alpha-2, ex: "BR"), `region`, `isp`, `asn` (apenas o número, ex: "AS28573" — extraído do campo `as` da API). Chaves na tabela config: `geoip_requests_this_minute`, `geoip_minute_window_start`, `geoip_cooldown_until` (rate limiting global).

### Migrações
- **v2** (`amssoft_fail2ban_migrate_v2`): cria tabela ai_suggestions se não existir
- **v3** (`amssoft_fail2ban_migrate_v3`): adiciona colunas filter_name, failregex, filter_created_at
- **v4** (`amssoft_fail2ban_migrate_v4`): multi-provider IA — migra chaves antigas para formato por provedor, garante `ai_active_provider`
- **v5** (`amssoft_fail2ban_migrate_v5`): cria tabela geo_cache para dados geográficos de IPs
- **v6** (`amssoft_fail2ban_migrate_v6`): limpa chave legada `ai_provider_mimo_protocol` (protocolo fixo OpenAI)

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
- **Mitigação de prompt injection:** instruções no system prompt, logs em `<log_data>` com aviso explícito

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

### Deduplicação (3 camadas)
1. **Whitelist pre-filter:** remove linhas cujos IPs são todos whitelisted/banidos/pendentes **antes** de enviar à IA. Economiza tokens — linhas com IPs irrelevantes nunca chegam à API. Implementado em `LogViewer::filterLinesByIPs()`, chamado por `AIController::ajaxAnalyzeLog()` e `AutoBanEngine::runAnalysis()`. Mantém linhas sem IP (podem ter padrões de ataque) e linhas com IPs mistos (whitelisted + não-whitelisted).
2. **Watermark por arquivo:** lê apenas bytes novos desde última análise (offset no banco)
3. **IP dedup (pós-IA):** `filterSuggestions()` remove sugestões para IPs já banidos/pendentes/whitelisted — safety net após a resposta da IA

**Comportamento do watermark:**
- Chave `ai_log_offset.{md5(path)}` é compartilhada entre AutoBanEngine (cron) e ajaxAnalyzeLog (manual). Ambos competem pelo mesmo ponteiro — decisão de design, não bug.
- Watermark usa **offset real lido** (via `ftell()`) em vez de `filesize()`. Quando o log tem mais linhas que o limite configurado (`ai_log_lines`), o watermark avança apenas até onde a leitura parou — as linhas restantes são lidas no próximo ciclo. Evita perda silenciosa de conteúdo.
- Watermark só avança após sucesso: atualização ocorre DEPOIS da chamada à IA e salvamento das sugestões. Se a API falhar, ou se o parse da resposta falhar (JSON inválido ou truncado), o watermark NÃO avança e o trecho será reanalisado na próxima tentativa.
- Parâmetro `force=1` no POST de `analyze_log` ignora o watermark e relê as últimas N linhas. Útil após trocar prompt ou modelo de IA. Quando force está ativo, o watermark NÃO é atualizado (para não perder bytes novos).
- **Rolling TTL da sessão:** `ai_analysis_session_start` é renovado a cada `analyze_log` bem-sucedido (após save + watermark). Se a chamada à IA falhar, o TTL NÃO é renovado — a sessão expira naturalmente se ficar 5min sem progresso. Isso permite que análises com 33+ logs durem indefinidamente enquanto houver progresso.
- **Skip client-side:** `list_logs` retorna `has_new` por log (comparação `filesize > watermark`). JS pula logs sem conteúdo novo sem request ao servidor. Limitação: `has_new` é calculado no momento do `list_logs` — se o log crescer entre `list_logs` e `analyze_log`, o skip é um falso positivo aceitável (capturado no próximo ciclo).
- **Check `is_readable()`:** tanto `ajaxAnalyzeLog()` quanto `AutoBanEngine` verificam `is_readable()` antes de processar. Se o arquivo não for legível (ex: www-data sem permissão), o controller retorna erro claro e o watermark NÃO é resetado. Evita bug progressivo onde `@filesize()` retorna `false` → `0 < storedOffset` → watermark resetado para 0.
- **Concorrência:** não há lock no read-write do watermark. Duas requisições simultâneas (duplo clique, cron + manual) podem ler o mesmo offset e processar o mesmo trecho. Pior caso: 1 chamada API duplicada. Sem perda de dados — `saveSuggestion()` faz upsert por IP e o watermark converge para o valor correto. Risco aceito como tolerável; optimistic lock não justifica a complexidade.
- **Pre-filter e watermark:** quando o whitelist pre-filter remove todas as linhas de um log, o watermark AVANÇA mesmo assim (evita reprocessar infinitamente o mesmo trecho). No `ajaxAnalyzeLog`, o watermark é atualizado antes do return quando `filtered=true`. No `AutoBanEngine`, o watermark já é atualizado antes do pre-filter (linha 162). Comportamento diferente entre os dois é intencional: o cron atualiza watermark logo após ler; o controller atualiza após sucesso da IA, mas com exceção para pre-filter vazio.

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

### GeoIP
Lookup de dados geográficos de IPs via API pública ip-api.com. Sem chave, sem instalação.

**Endpoint:** `http://ip-api.com/json/{ip}?fields=countryCode,country,regionName,isp,as,status,message`
**Rate limit:** 45 req/min (HTTP). Timeout: 3s por request.

**Parsing do campo `as`:** a API retorna `as` como string completa (ex: "AS28573 Claro NXT Telecomunicacoes Ltda"). O `fetchFromApi()` extrai o número ASN com `preg_match('/^(AS\d+)/i', ...)` → `asn = "AS28573"`. Se `isp` estiver vazio, o nome do AS (tudo após o ASN) é usado como fallback para `isp`.

**Classe `lib/GeoIP.php`:**
- `lookup(string $ip): ?array` — lookup individual
- `bulkLookup(array $ips): array` — cache-first, batch lookup. Retorna array keyado por IP com null para misses.
- `isAvailable(): bool` — testa conectividade (usa IP fixo 8.8.8.8, resultado não salvo no cache)
- `getStatus(): array` — info para UI (requests restantes, cooldown ativo, etc.)
- `clearCache(): void` — trunca tabela geo_cache
- `cleanExpiredGeoCache(int $ttlDays): void` — remove registros expirados (lazy cleanup)
- `countryToFlag(string $code): string` — ISO code → emoji bandeira via Unicode Regional Indicator (fórmula: `0x1F1E6 - ord('A') + ord($letter)`). Fallback: 🌐 se código não tiver exatamente 2 caracteres. **Edge case:** a fórmula gera emoji para qualquer par de 2 letras (incluindo códigos ISO inexistentes como "XX"), mas a API ip-api.com só retorna códigos ISO válidos ou vazio — este cenário não ocorre em produção.
- `formatGeo(?array $geo): string` — formata para exibição (ex: "🇧🇷 São Paulo — Claro NXT"). Retorna "—" se null.

**Rate limiting (3 camadas):**
1. **Global:** contador `geoip_requests_this_minute` na tabela config (safety limit: 40/min). Race condition entre admins simultâneos é limitação conhecida (impacto baixo — ver Limitações Conhecidas).
2. **Batch limit dinâmico:** `min(remaining, MAX_REQUESTS_PER_CALL=10)` por carregamento de página.
3. **Cooldown 429:** se API retornar HTTP 429, persiste `geoip_cooldown_until = now() + 60s` no banco. Checado no início de `bulkLookup` antes de qualquer request — bloqueia todos os requests HTTP durante o cooldown.

**Cache:** tabela `mod_amssoft_fail2ban_geo_cache` com TTL 30 dias. `bulkLookup` faz 1 query `WHERE IN` com `DATE_SUB(NOW(), INTERVAL ? DAY)` para filtrar expirados. HTTP só para misses. Upsert batch via `INSERT ... ON DUPLICATE KEY UPDATE` em query única.

**Display:** `<small class="amsfb-geo-info">` abaixo do IP em todas as telas. Log Viewer usa tooltip `title` no botão inline (com escape HTML no JS). Modal de ban usa `textContent` (seguro contra XSS).

**Filtro de IPs privados:** `fetchFromApi()` verifica `FILTER_FLAG_NO_PRIV_RANGE` + `FILTER_FLAG_NO_RES_RANGE` antes do curl. IPs privados (10.x, 172.16-31.x, 192.168.x), loopback (127.x), link-local (169.254.x) e reserved (0.0.0.0) retornam `null` sem request HTTP — economiza quota do rate limit.

**Configuração:** seção "GeoIP" em ai_settings.tpl — botão "Testar conexão" (chama `do=ping_geoip`) e botão "Limpar cache geo" (chama `do=clear_geoip_cache` com confirmação). Rate limit info exibido na tela (lido do banco, sem HTTP).

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
- Validadas com CSRF token (rotacionado após cada uso, exceto `fetch_lines` — ver SEC-7)
- Respondem com JSON

### Jails (action=jails)
- `do=enable` — habilita jail
- `do=disable` — desabilita jail
- `do=remove` — remove jail
- `do=reload_all` — reload geral do fail2ban

### IA (action=ai)
- `do=approve` — aprova sugestão (bane IP via provedor ativo)
- `do=reject` — rejeita sugestão
- `do=run_now` — executa análise manual via provedor ativo (legado, usado em ai_settings)
- `do=list_logs` — lista logs disponíveis para análise (rate limit: 60s, inicia sessão de análise). Retorna metadata enriquecida por log: `filesize`, `watermark`, `has_new` (boolean). JS usa `has_new` para pular logs sem conteúdo novo sem request ao servidor.
- `do=analyze_log` — analisa um único log (requer sessão ativa, usa watermark, retorna sugestões salvas). Aceita `force=1` no POST para ignorar watermark e reanalisar (útil após trocar prompt/modelo). Campos extras no JSON de resposta: `parse_failed` (boolean), `truncated` (boolean — resposta cortada por max_tokens). Em caso de 429 do provedor, retorna `{success: false, error: 'rate_limited', retry_after: 60}`.
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
- **[SEC-16]** Mitigação de prompt injection (system prompt + tags `<log_data>`)
- **[SEC-17]** Base URL editável: validação https:// + bloqueio de IPs privados/localhost/link-local 169.254.x.x (SSRF defense)
- **[SEC-18]** `ai_active_provider` validado contra registry antes de persistir
- **[SEC-19]** Erros de API: mensagem genérica no frontend, detalhes nunca expostos
- **[SEC-20]** Validação de IDs em bulk actions: JSON array de ints positivos, max 200, verificação de `status = 'pending'` antes de processar. Validação de `country_code` em `get_ids_by_country`: regex `/^[A-Z]{2}$/` ou vazio.

## Problemas Conhecidos

| Problema | Solução |
|---|---|
| `deactivate()` não remove tabela `geo_cache` | Bug conhecido: `amssoft_fail2ban_deactivate()` dropa logs/config/ai_suggestions mas não geo_cache. Corrigir adicionando `Capsule::schema()->dropIfExists('mod_amssoft_fail2ban_geo_cache');` |
| sudo não instalado | `apt-get install -y sudo` |
| fail2ban não instalado | `apt-get install -y fail2ban` |
| fail2ban não inicia (sshd sem log) | `[sshd] enabled = false` no jail.local |
| www-data sem sudo | Verificar `/etc/sudoers.d/amssoft_fail2ban` |
| "Erro ao criar jail" | `chown root:www-data jail.local && chmod 0664 jail.local` |
| "Falha ao criar arquivo de filtro" | Re-aplicar sudoers (v3 adicionou regras de cp/chmod) |
| Aviso "sudoers desatualizado" | Re-aplicar sudoers do setup/ |
| "Arquivo não legível pelo servidor web" (not_readable) | Logs `root:adm 640` não são legíveis por www-data. Corrigir: `chown root:www-data /var/log/apache2/access_whmcs.log /var/log/fail2ban.log` (e outros logs necessários). Ver seção "Permissões de arquivos de log". |

### Limitações Conhecidas (edge cases aceitos)

| Cenário | Impacto | Mitigação |
|---|---|---|
| **Logrotate copytruncate** — se o analysis rodar no exato momento em que o logrotate zera o arquivo (janela de ~ms), `currentSize < storedOffset` e o offset reseta para 0. O trecho recém-escrito antes da rotação pode ser reanalisado. | Baixo: reprocessamento pontual, sem perda de dados. Sugestões duplicadas são prevenidas pelo upsert por IP. | Nenhuma — edge case tolerável. Se o logrotate rodar a cada 24h, a janela de colisão é ~ms vs 86400s. |
| **Concorrência no watermark** — duas requisições simultâneas (duplo clique, cron + manual) podem ler o mesmo offset e processar o mesmo trecho. | Baixo: 1 chamada API duplicada. Watermark converge; sugestões não duplicam (upsert por IP). | Nenhuma — risco aceito. Ver seção "Comportamento do watermark". |
| **Race condition no rate limit GeoIP** — o estado (`requests_this_minute`, `minute_window_start`, `cooldown_until`) é lido e escrito sem lock. Dois admins simultâneos podem ler o mesmo valor, incrementar, e escrever. | Baixo: pior caso 2-3 requests extras perto do limite de 45. Não causa falha nem perda de dados. | Margem de segurança: safety limit = 40 (não 45). Cooldown de 429 cobre o caso extremo. |
| **Cache geo com ASN antigo** — registros cacheados antes da correção do parsing (que extrai apenas o número ASN) podem ter `asn` com string completa (ex: "AS396982 Google LLC" em vez de "AS396982"). | Baixo: campo `asn` exibido como tooltip/coluna secundária, não afeta funcionalidade. | TTL de 30 dias: registros antigos são substituídos automaticamente. `cleanExpiredGeoCache()` acelera a limpeza se necessário. |
| **`has_new` stale no skip client-side** — `list_logs` calcula `has_new` no momento da requisição. Se o log crescer entre `list_logs` e o `analyze_log` daquele arquivo (possível em logs ativos como Apache), o JS pula mesmo havendo conteúdo novo. | Baixo: conteúdo novo é capturado no próximo ciclo de análise (próximo clique ou cron). | Nenhuma — edge case tolerável. O watermark do servidor é a fonte de verdade; o skip client-side é otimização, não gate. |

**Observação em produção (2026-06-30):** `whmcs_auth.log` estava com watermark=3884818 mas arquivo=0 bytes — instância real do edge case de rotação. O próximo `analyze_log` vai resetar o offset para 0 e reanalisar do início (comportamento correto).

### Bugs críticos corrigidos (2026-07-01)

Três bugs causavam perda silenciosa de dados de log. Todos corrigidos no mesmo commit:

| Bug | Problema | Correção |
|---|---|---|
| **LogViewer cap 500** | `readLines()` e `readNewLinesFromOffset()` limitavam a 500 linhas (hard-coded), ignorando `ai_log_lines` configurado pelo admin | `min(500)` → `min(1000)` em ambos os métodos |
| **Watermark reset por permissão** | `www-data` não lia logs `root:adm 640` → `@filesize()` retornava `false` → `0 < storedOffset` → watermark resetado para 0 | `is_readable()` check antes de processar + permissões corrigidas (`root:www-data 640`) |
| **Watermark avançava para filesize** | Watermark era atualizado para `filesize()` em vez do offset real lido → linhas entre o offset de leitura e o final do arquivo eram permanentemente perdidas | `readNewLinesFromOffset()` retorna `['lines' => [], 'offset' => int]` com `ftell()`; watermark usa offset real |

**Verificação de cobertura (busca global):**
- `min(500` — zero ocorrências em LogViewer.php
- `$currentSize` para watermark — zero ocorrências em AIController.php e AutoBanEngine.php
- `readNewLinesFromOffset` — todas as chamadas atualizadas para novo retorno
- `Database::setConfig($offsetKey` — ambas usam `$readOffset` (ftell), não `$currentSize` (filesize)

**Testes manuais executados:**
- `readLines(path, 1000)` retorna 1000 linhas (antes: 500) ✓
- `readNewLinesFromOffset(path, 0, 1000)` com log de 10.000 linhas: offset=97.450 < filesize=984.535 ✓
- Progressivo: 10 ciclos × 1000 linhas → offset avança 97K → 196K → ... → 984K = filesize ✓
- Arquivo pequeno (300 linhas < 1000): offset=filesize ✓
- `is_readable()` como www-data: arquivo ilegível → watermark preservado ✓
- Cron progressivo: 3 execuções → offset 0 → 97K → 196K → 294K ✓

### Bugs corrigidos (2026-07-01 — CSRF e carregamento)

| Bug | Problema | Correção |
|---|---|---|
| **LogViewer: AMSFB undefined** | Script inline do logviewer.tpl chamava `fetchLines()` imediatamente, mas `window.AMSFB` era definido em `amssoft_fail2ban.js` carregado pelo layout **depois** do conteúdo | IIFE envolvida em `DOMContentLoaded` — garante que scripts do layout já carregaram |
| **LogViewer: CSRF no fetch_lines** | Race condition: `fetch_lines` (a cada 5s) usava token antigo quando `analyze`/`ban_ip` rotacionavam o CSRF token | Retry automático (1x) quando erro contém "CSRF". Router injeta token atual na resposta mesmo em erro |
| **IA: CSRF no list_logs/analyze_log** | Fluxo "Analisar agora" não tinha retry CSRF. Se token era rotacionado por sessão expirada ou concorrência, o fluxo falhava sem recuperação | `doListLogs()` e `doAnalyzeLog()` com retry automático (1x) em ambos os endpoints |

**Padrão de retry CSRF (adotado em todos os endpoints AJAX):**
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
- **Watermark só após sucesso** — atualizar offset de watermark SOMENTE depois que a chamada à IA e o salvamento das sugestões tiverem sucesso. Se a API falhar, o watermark não avança e o log será reanalisado.
