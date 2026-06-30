# CLAUDE.md — AMS SOFT Fail2Ban Manager

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
│   ├── LogViewer.php           # Leitura de logs com highlight (suspicious/error patterns) + readNewLinesFromOffset()
│   ├── AIAnalyzer.php          # Integração multi-provider IA (Anthropic, MiMo) — análise + geração de failregex
│   ├── FilterManager.php       # Cria filtros (.conf) e jails para filtros gerados pela IA
│   ├── AutoBanEngine.php       # Motor de ban automático (3 modos: suggestion/auto/threshold)
│   └── GeoIP.php               # Lookup geográfico via ip-api.com (cache + rate limiting)
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

4 tabelas (prefixo `mod_amssoft_fail2ban_`):

### mod_amssoft_fail2ban_logs
Log de eventos (ban/unban/manual_ban/manual_unban). Indexada por ip, jail, timestamp.

### mod_amssoft_fail2ban_config
Key-value store genérico. Usado para:
- **Multi-provider IA:**
  - `ai_active_provider` — provedor ativo (`anthropic` | `mimo`)
  - `ai_provider_{name}_api_key` — chave API criptografada por provedor
  - `ai_provider_{name}_model` — modelo selecionado por provedor
  - `ai_provider_{name}_protocol` — protocolo escolhido (provedores com seletor)
  - `ai_provider_{name}_base_url` — endpoint (provedores editáveis)
  - `ai_provider_{name}_last_ping` — último ping OK por provedor
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

### mod_amssoft_fail2ban_ai_suggestions
Sugestões da IA com status (pending/approved/rejected/auto_executed). Inclui campos v3: `filter_name`, `failregex`, `filter_created_at`. **Agrupamento por país:** `getPendingGroupedByCountry()` faz JOIN com `geo_cache` para agrupar pendentes por `country_code`. `getPendingIdsByCountry($cc)` retorna IDs pendentes de um país específico (vazio = sem geo data). Usado para ações em massa (bulk approve/reject) na UI.

### mod_amssoft_fail2ban_geo_cache
Cache de dados geográficos de IPs (via ip-api.com). PRIMARY KEY em `ip`, com `updated_at` para TTL (30 dias). Campos: `country` (nome por extenso), `country_code` (ISO 3166-1 alpha-2, ex: "BR"), `region`, `isp`, `asn` (apenas o número, ex: "AS28573" — extraído do campo `as` da API). Chaves na tabela config: `geoip_requests_this_minute`, `geoip_minute_window_start`, `geoip_cooldown_until` (rate limiting global).

### Migrações
- **v2** (`amssoft_fail2ban_migrate_v2`): cria tabela ai_suggestions se não existir
- **v3** (`amssoft_fail2ban_migrate_v3`): adiciona colunas filter_name, failregex, filter_created_at
- **v4** (`amssoft_fail2ban_migrate_v4`): multi-provider IA — migra chaves antigas para formato por provedor, garante `ai_active_provider`
- **v5** (`amssoft_fail2ban_migrate_v5`): cria tabela geo_cache para dados geográficos de IPs

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
- **`readLines($path, $lines)`** — lê as últimas N linhas do arquivo (usado pelo Log Viewer e pelo `force=1`)
- **`readNewLinesFromOffset($path, $offset, $maxLines)`** — lê bytes novos a partir de um offset (usado pelo watermark). Usa `fseek()` + `stream_get_contents()` (não carrega arquivo inteiro). Proteção contra offset inválido (fallback para 0 se offset > filesize).

**Descoberta e análise:**
- **`getAvailableLogs($extra)`** — varre logs bem conhecidos (`WELL_KNOWN_LOGS`), custom logs do DB (`custom_log.*`), logpaths de jails (`logpath.*`), e `fail2ban.log`
- **`extractIPs($lines)`** — extrai IPv4/IPv6 de linhas de log
- **`highlightSuspicious($lines)`** — marca linhas com classes CSS (normal/suspicious/error)
- **`isValidPath($path)`** — validação de path (SEC-8)

## Integração com IA (Multi-Provider)

### AIAnalyzer — Registry de Provedores

Arquitetura multi-provider com dispatch por **protocolo** (não por nome). Cada provedor define protocolo, modelos, e se a URL é editável.

```php
AIAnalyzer::PROVIDERS = [
    'anthropic' => [
        'protocol' => 'anthropic',        // protocolo próprio
        'models'   => ['claude-haiku-4-5-20251001', 'claude-sonnet-4-6', 'claude-opus-4-6'],
        ...
    ],
    'mimo' => [
        'protocol' => 'anthropic',        // default, mas editável via seletor na UI
        'has_protocol_selector' => true,   // mostra seletor Anthropic/OpenAI
        'protocol_options' => [
            'anthropic' => ['base_url' => 'https://token-plan-sgp.xiaomimimo.com/anthropic'],
            'openai'    => ['base_url' => 'https://token-plan-sgp.xiaomimimo.com/v1'],
        ],
        'models' => ['mimo-v2.5-pro', 'mimo-v2.5'],
        ...
    ],
];
```

Adicionar provedor futuro = 1 entrada no array `PROVIDERS`.

**Provedores suportados:**
- **Anthropic (Claude)** — protocolo próprio, endpoint `https://api.anthropic.com/v1/messages`
- **MiMo (Xiaomi)** — suporta protocolo Anthropic e OpenAI, cliente escolhe via seletor na UI

**Seletor de protocolo (MiMo):**
Provedores com `has_protocol_selector => true` mostram radio buttons na UI para o cliente escolher entre protocolos disponíveis. O endpoint é aplicado automaticamente:
- **Anthropic:** `https://token-plan-sgp.xiaomimimo.com/anthropic` → código adiciona `/v1/messages`
- **OpenAI:** `https://token-plan-sgp.xiaomimimo.com/v1` → código adiciona `/chat/completions`

O método `buildEndpointUrl()` monta a URL final a partir da base + path do protocolo.

**Configuração no banco (chaves dinâmicas por provedor):**
- `ai_active_provider` — provedor ativo (`anthropic` | `mimo`)
- `ai_provider_{name}_api_key` — chave API criptografada (AES-256-CBC)
- `ai_provider_{name}_model` — modelo selecionado
- `ai_provider_{name}_protocol` — protocolo escolhido (apenas para provedores com seletor)
- `ai_provider_{name}_base_url` — endpoint (apenas para provedores com `needs_base_url`)

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
- Prompt customizável pelo admin (max 8000 chars)
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

### Deduplicação (2 camadas)
1. **Watermark por arquivo:** lê apenas bytes novos desde última análise (offset no banco)
2. **IP dedup:** ignora IPs já banidos no fail2ban + IPs com sugestão pendente

**Comportamento do watermark:**
- Chave `ai_log_offset.{md5(path)}` é compartilhada entre AutoBanEngine (cron) e ajaxAnalyzeLog (manual). Ambos competem pelo mesmo ponteiro — decisão de design, não bug.
- Watermark só avança após sucesso: atualização ocorre DEPOIS da chamada à IA e salvamento das sugestões. Se a API falhar, o trecho será reanalisado na próxima tentativa.
- Parâmetro `force=1` no POST de `analyze_log` ignora o watermark e relê as últimas N linhas. Útil após trocar prompt ou modelo de IA. Quando force está ativo, o watermark NÃO é atualizado (para não perder bytes novos).
- **Concorrência:** não há lock no read-write do watermark. Duas requisições simultâneas (duplo clique, cron + manual) podem ler o mesmo offset e processar o mesmo trecho. Pior caso: 1 chamada API duplicada. Sem perda de dados — `saveSuggestion()` faz upsert por IP e o watermark converge para o valor correto. Risco aceito como tolerável; optimistic lock não justifica a complexidade.

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
- Validadas com CSRF token (rotacionado após cada uso)
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
- `do=list_logs` — lista logs disponíveis para análise (rate limit: 60s, inicia sessão de análise)
- `do=analyze_log` — analisa um único log (requer sessão ativa, usa watermark, retorna sugestões salvas). Aceita `force=1` no POST para ignorar watermark e reanalisar (útil após trocar prompt/modelo)
- `do=ping_api` — testa conexão com API (aceita `provider` e `protocol` no POST)
- `do=save_settings` — salva configurações (multi-provider: provedor ativo, protocolo, chave, modelo)
- `do=create_filter` — cria filtro fail2ban a partir de sugestão (usa provedor ativo)
- `do=bulk_approve_country` — aprova todas as sugestões pendentes de um país (best-effort, retorna `approved_ids`, `failed_ids`, `dismissed_ids`)
- `do=bulk_reject_country` — rejeita todas as sugestões pendentes de um país (batch UPDATE)

**Fluxo "Analisar agora" (sequencial com progresso):**
1. JS chama `do=list_logs` → retorna todos os logs disponíveis (rate limit 60s, marca sessão)
2. Para cada log: JS chama `do=analyze_log` com path → analisa, salva sugestões, retorna
3. Linhas são adicionadas dinamicamente na tabela com 5 botões de ação
4. Watermark (`ai_log_offset.{md5}`) pula logs sem conteúdo novo (resposta com `message` = pulado)
5. Sessão expira em 300s (previne chamada direta via script)
6. Mensagem final mostra breakdown: N analisado(s), M pulado(s), X sugestão(ões)

**Rate limiting (SEC-10):**
- `do=list_logs`: 60s entre sessões (protege contra abuso)
- `do=analyze_log`: sem rate limit individual (progresso sequencial rápido), mas requer sessão ativa
- `do=run_now`: 60s (legado, mantido para ai_settings)

### GeoIP (action=ai)
- `do=ping_geoip` — testa conectividade com ip-api.com (usa IP fixo 8.8.8.8)
- `do=clear_geoip_cache` — trunca tabela geo_cache

### Log Viewer (action=logviewer)
- `do=fetch_lines` — lê linhas do log (retorna `geo_data` com lookup dos IPs mais frequentes, máx 20)
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
- **[SEC-10]** Rate limiting: 60s em `list_logs` (início de sessão), sessão de análise expira em 300s, `analyze_log` requer sessão ativa
- **[SEC-11]** Limite de 8000 chars no prompt customizado
- **[SEC-12]** CSRF validado incondicionalmente em todas as requisições AJAX POST
- **[SEC-14]** Evitar `Capsule::raw()` com variável interpolada
- **[SEC-15]** Validação de status contra ENUM antes de UPDATE
- **[SEC-16]** Mitigação de prompt injection (system prompt + tags `<log_data>`)
- **[SEC-17]** Base URL editável: validação https:// + bloqueio de IPs privados/localhost/link-local 169.254.x.x (SSRF defense)
- **[SEC-18]** `ai_active_provider` validado contra registry antes de persistir
- **[SEC-19]** Erros de API: mensagem genérica no frontend, detalhes nunca expostos
- **[SEC-20]** Validação de `country_code` em bulk actions: regex `/^[A-Z]{0,2}$/` (2 letras maiúsculas ou vazio)

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

### Limitações Conhecidas (edge cases aceitos)

| Cenário | Impacto | Mitigação |
|---|---|---|
| **Logrotate copytruncate** — se o analysis rodar no exato momento em que o logrotate zera o arquivo (janela de ~ms), `currentSize < storedOffset` e o offset reseta para 0. O trecho recém-escrito antes da rotação pode ser reanalisado. | Baixo: reprocessamento pontual, sem perda de dados. Sugestões duplicadas são prevenidas pelo upsert por IP. | Nenhuma — edge case tolerável. Se o logrotate rodar a cada 24h, a janela de colisão é ~ms vs 86400s. |
| **Concorrência no watermark** — duas requisições simultâneas (duplo clique, cron + manual) podem ler o mesmo offset e processar o mesmo trecho. | Baixo: 1 chamada API duplicada. Watermark converge; sugestões não duplicam (upsert por IP). | Nenhuma — risco aceito. Ver seção "Comportamento do watermark". |
| **Race condition no rate limit GeoIP** — o estado (`requests_this_minute`, `minute_window_start`, `cooldown_until`) é lido e escrito sem lock. Dois admins simultâneos podem ler o mesmo valor, incrementar, e escrever. | Baixo: pior caso 2-3 requests extras perto do limite de 45. Não causa falha nem perda de dados. | Margem de segurança: safety limit = 40 (não 45). Cooldown de 429 cobre o caso extremo. |
| **Cache geo com ASN antigo** — registros cacheados antes da correção do parsing (que extrai apenas o número ASN) podem ter `asn` com string completa (ex: "AS396982 Google LLC" em vez de "AS396982"). | Baixo: campo `asn` exibido como tooltip/coluna secundária, não afeta funcionalidade. | TTL de 30 dias: registros antigos são substituídos automaticamente. `cleanExpiredGeoCache()` acelera a limpeza se necessário. |

**Observação em produção (2026-06-30):** `whmcs_auth.log` estava com watermark=3884818 mas arquivo=0 bytes — instância real do edge case de rotação. O próximo `analyze_log` vai resetar o offset para 0 e reanalisar do início (comportamento correto).

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
