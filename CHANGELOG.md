# CHANGELOG

## 2026-07-18 — Fix: Filtros fail2ban com regex inválida quebravam o serviço

### Problema

- **Sintoma:** fail2ban não iniciava. Erro: `'%' must be followed by '%' or '('` e `unbalanced parenthesis`. Módulo mostrava aviso "sudo não está funcionando".
- **Causa raiz:** Dois filtros gerados pela IA tinham regex inválidas:
  - `amsfb-apache-language-scanner.conf` — `%27` (apóstrofo URL-encoded) não escapado. fail2ban interpreta `%` como caractere de formatação.
  - `amsfb-cms-scanner-bot.conf` — `\<HOST>` com escape incorreto. fail2ban não reconhece `<HOST>` escapado.
- **Correção manual:** Filtros corrigidos no servidor (`%%27` e `<HOST>`).
- **Correção no código:** `FilterManager` agora previne ambos os casos.

### Arquivos modificados

| Arquivo | Mudança |
|---|---|
| `lib/FilterManager.php` | `validateFailregex()` rejeita `\<HOST>`; `createFilter()` escapa `%` como `%%` |

---

## 2026-07-04 — Fix: Botão "Desbanir" não funcionava (CSRF stale + ordem de scripts)

### Problema

- **Sintoma:** Ao clicar em "Desbanir" na página IPs Banidos, nada acontecia. O IP permanecia banido.
- **Causa raiz (CSRF):** O botão usava `<form method="post">` tradicional com CSRF token impresso no HTML hidden field. Quando o admin navegava entre abas do módulo antes de clicar "Desbanir", o CSRF token era rotacionado por outras requisições AJAX ([SEC-7]), tornando o token no form stale. O POST falhava silenciosamente com flash "Token CSRF inválido" que auto-dismissava em 5 segundos.
- **Causa raiz (JS):** A primeira tentativa de correção usou `window.AMSFB.post()` dentro de um script inline no template. Mas o layout.tpl carrega `amssoft_fail2ban.js` (que define `window.AMSFB.post`) **após** o `$content` (onde o script inline é renderizado). Quando o IIFE era executado, `window.AMSFB.post` ainda não existia.
- **Teste fail2ban-client:** `sudo fail2ban-client set ai-bans unbanip 160.20.161.217` retornou `1` (sucesso) — o fail2ban-client funcionava corretamente.

### Correção final

- **Template `ips.tpl`:** Convertido unban de form POST tradicional para `fetch()` direto no JavaScript inline. Não depende de `amssoft_fail2ban.js` carregar primeiro. Usa `window.AMSFB.csrfToken` (se disponível) ou fallback para input hidden. Handler anexado diretamente nos botões com `data-ip` e `data-jail`.
- **Controller `IpsController.php`:** Adicionado método `handleAjax(string $do, array $post): string` para processar unban/ban via AJAX. Inclui fallback: se `unbanIP()` falhar, verifica se o IP já não está banido (pode ter sido removido por outro processo).
- **Resultado:** Botão "Desbanir" funciona independentemente de quantas requisições AJAX tenham sido feitas antes. Feedback imediato (flash message + remoção da linha com animação).

### Arquivos modificados

| Arquivo | Mudança |
|---|---|
| `templates/ips.tpl` | Substituiu `<form method="post">` por `<button>` com handler `fetch()` direto |
| `controllers/IpsController.php` | Adicionado `handleAjax()` para unban/ban via AJAX |

---

## 2026-07-04 — Segurança: prompt injection, ignoreip, heurística de fallback

### Prompt injection via delimitador de log (SEC-16)

- **Vulnerabilidade:** payload `</log_data>` no User-Agent evada detecção em ~70% no MiMo (modelo retorna `[]` vazio). Anthropic resiste 100%.
- **Causa raiz:** fraqueza do modelo MiMo, não do código. Qualquer sintaxe de fechamento de bloco (XML-like ou não) tem a mesma taxa de evasão.
- **Correção 1:** delimitador aleatório por requisição (`<log_data_{token}>`) — `AIAnalyzer::buildPrompt()` e `generateFilterRegex()`.
- **Correção 2:** heurística de fallback regex quando IA retorna `[]` — `AutoBanEngine::heuristicFallback()`. 15 padrões de ataque + detecção de UA >500 chars. Confidence 80 (acima do threshold). Intencionalmente "burra" (regex, não IA) — resistente a prompt injection por natureza.
- **Aviso no painel:** alerta quando MiMo é selecionado como provedor (resistência reduzida a prompt injection).
- **Documentação:** CLAUDE.md SEC-16 atualizado com taxas de evasão por provedor.

### ai-bans sem ignoreip + saveJail() whitelist incompleta

- **Problema:** `ignoreip = 127.0.0.1` sumiu do `ai-bans` após round-trip de `saveJail()`. Causa: `ignoreip` não estava na whitelist de campos permitidos.
- **Correção:** `ignoreip` adicionado ao `$allowed` em `JailConfig::saveJail()`. Migration v11 verifica `logpath` + `ignoreip` em `ai-bans`.
- **Falso positivo:** 127.0.0.1 banido por 43 min (nossos testes curl geraram tráfego que a IA classificou corretamente como scan).

### Arquivos modificados

| Arquivo | Mudança |
|---|---|
| `lib/AIAnalyzer.php` | Delimitador aleatório em `buildPrompt()` e `generateFilterRegex()` |
| `lib/AutoBanEngine.php` | `heuristicFallback()` + `buildHeuristicSuggestion()`, integrado no batch loop |
| `lib/JailConfig.php` | `ignoreip` adicionado ao `$allowed` de `saveJail()` |
| `amssoft_fail2ban.php` | Migration v11: `logpath` + `ignoreip` para `ai-bans` |
| `templates/ai_settings.tpl` | Aviso de segurança quando MiMo é selecionado |

---

## 2026-07-03 — Fix: Filtros auto-criados ineficazes (logpath errado + failregex incompleto)

### Bug 1 — Logpath errado por inferência frágil

- **Problema:** `detectLogPathSafe()` inferia logpath por keywords no failregex. Scanners web (`GET`, `HTTP/1.1`) caíam no fallback genérico → `whmcs_auth.log` → incompatível com formato Apache.
- **Correção:** Propagar `source_log` do `$path` real do pipeline. `saveSuggestion()` salva, `analyzeFilterNameOccurrences()` retorna `best_source_log`, `autoCreateFilterAndBan()` usa direto (fallback para `detectLogPathSafe` para dados antigos).
- **Migration v9:** coluna `source_log` em `mod_amssoft_fail2ban_ai_suggestions`.
- **Resultado:** filtros criados apontam para o log correto (`access_whmcs.log` para scanners, `whmcs_auth.log` para brute force).

### Bug 2 — best_failregex escolhe 1 de N padrões

- **Problema:** `analyzeFilterNameOccurrences()` retornava 1 failregex. Quando todos tinham contagem 1, pegava o mais antigo (não o mais representativo).
- **Correção:** Retorna `all_failregex` (top 5 por frequência, ordenação determinística por `created_at DESC`). `executeBan()` combina com `\n` para filtro multi-padrão (fail2ban suporta múltiplas linhas `failregex`).
- **validateFailregex():** limite aumentado de 1000→5000 chars para suportar multi-pattern.

### Limpeza

- Filtros `amsfb-cms-scanner-bot` e `amsfb-api-version-probe` removidos (estavam inertes).
- `filter_name` no banco preservado — próximo gate recria com correto.

### Arquivos modificados

| Arquivo | Mudança |
|---|---|
| `amssoft_fail2ban.php` | Migration v9 (`source_log` column) |
| `lib/Database.php` | `saveSuggestion()` salva `source_log`; `analyzeFilterNameOccurrences()` retorna `all_failregex` + `best_source_log` |
| `lib/AutoBanEngine.php` | `runAnalysis()` propaga `source_log`; `executeBan()` usa `source_log` + multi-pattern |
| `lib/FilterManager.php` | `getAllowedLogs()` público; `validateFailregex()` limite 5000 |
| `controllers/AIController.php` | `ajaxAnalyzeLog()` propaga `source_log` |

---

## 2026-07-03 — Fix: Lock files com permissão errada causavam falso "analysis_locked"

### Problema

Lock files em `/tmp/amsfb_log_*.lock` eram criados pelo cron (root) com
permissão 644. Quando o painel web (www-data) tentava `fopen('c')`, falhava
com "Permission denied". O código tratava `fopen()===false` igual a
`flock()===false`, reportando "analysis_locked" quando na verdade era
permissão — não concorrência real.

**Impacto:** Se o cron rodava primeiro (a cada 4 min), toda análise via
painel web falhava em TODOS os logs. IA só enxergava logs quando o painel
rodava antes do cron (raro).

### Correção

1. **`lib/LogLock.php`** — classe compartilhada de lock com:
   - Diretório dedicado `data/locks/` (dentro do projeto) com setgid (2770)
   - `touch()` + `chmod(0660)` antes de `fopen()` — setgid herda grupo
   - `detectWebGroup()` com detecção automática via diretório do WHMCS
   - Fallback configurável via campo `web_process_group`
   - Retorno estruturado `{fp, reason}` — sem recalcular motivo

2. **`lib/AutoBanEngine.php`** — `acquireLogLock()` delega para `LogLock`,
   log com `reason` direto da fonte (sem reconstrução paralela)

3. **`controllers/AIController.php`** — inline lock substituído por
   `LogLock::acquire()` + `LogLock::release()`

4. **`amssoft_fail2ban.php`** — migrate v8:
   - ENUM expandido com `lock_config_warning`
   - Setup do diretório de lock
   - Campo `web_process_group` na config

### Segurança

- `data/locks/` é `2770 www-data:www-data` — sem acesso world, .htaccess bloqueia HTTP
- Lock files são `660 root:www-data` — setgid herda grupo do diretório
- Grupo detectado em runtime (não hardcodado `www-data`)
- **NÃO é necessário `chown root:www-data data/locks/`** — setgid funciona com `www-data:www-data`
- Nginx: documentado no README (`.htaccess` não funciona no Nginx)

### Modo degradado

Se o grupo do `data/locks/` for `root` (configuração incorreta), o sistema
entra em modo degradado: análise continua SEM lock, `lock_config_warning` é
logado no dashboard. Não bloqueia a IA — apenas perde proteção de concorrência.

### Testes

- Root adquire lock → www-data recebe `locked_by_other` (concorrência OK)
- Root libera → www-data adquire (cross-user OK)
- Lock file criado como `root:www-data 660` (setgid OK)
- Diretório `www-data:www-data 2770` (sem chown) → funciona perfeitamente
- Diretório `root:root 2770` → modo degradado com warning

---

## 2026-07-03 — Fix: TypeError em detectLogPathSafe + cleanup de órfão no catch

Bug encontrado em produção pelo monitoramento de tráfego real (cms-scanner-bot atingiu gate).

### Problema

- `FilterManager::detectLogPathSafe()` declarava `string $evidenceJson` mas recebia `array` de `AutoBanEngine::autoCreateFilterAndBan()` (evidence já decodificada do JSON).
- `TypeError` era capturada pelo `catch (\Throwable)` mas o bloco de cleanup de órfão (linhas 429-440) ficava no `if ($logpath === null)` — nunca alcançado quando o erro era uma exceção, não um retorno `null`.
- Resultado: `amsfb-cms-scanner-bot.conf` criado no disco, jail não criada, filtro órfão não removido.

### Correção

1. **`FilterManager::detectLogPathSafe()` e `detectLogPath()`:** assinatura alterada para `array|string $evidenceJson`. Normalização no topo: `if (is_array($evidenceJson)) $evidenceJson = json_encode($evidenceJson)`.
2. **`AutoBanEngine::autoCreateFilterAndBan()` catch block:** adicionado cleanup de órfão antes do log de erro. Verifica `$isNewFilter && isset($filterManager)` antes de chamar `removeFilter()`.
3. **Filtro órfão limpo:** `amsfb-cms-scanner-bot.conf` removido manualmente do disco.

### Arquivos modificados

| Arquivo | Mudança |
|---|---|
| `lib/FilterManager.php` | `detectLogPathSafe()` e `detectLogPath()` aceitam `array\|string` |
| `lib/AutoBanEngine.php` | catch block com cleanup de órfão + `isset($filterManager)` guard |

---

## 2026-07-03 — Lock de concorrência: cron vs. "Analisar agora" (auditado + testado)

Auditoria de concorrência identificou que cron automático e clique manual em "Analisar agora" podiam processar o mesmo log simultaneamente, gerando chamada de API duplicada. Implementado lock por log com `flock(LOCK_EX | LOCK_NB)`.

### 1. Lock por log em AutoBanEngine (runAnalysis)

- **Problema:** Nenhum mecanismo impedia cron e manual de processar o mesmo arquivo de log ao mesmo tempo.
- **Correção:** `acquireLogLock()` com `realpath()` + `md5()` por path. Lock file: `/tmp/amsfb_lock_{md5}.lock`. `is_readable()` verificado **antes** do lock (evita criar lock files para logs inexistentes).
- **`$allLocked`:** muda para `false` quando lock é adquirido com sucesso. `_locked_out` só retorna quando nenhum lock foi adquirido.
- **Observabilidade:** `Database::logEvent('', '', 'analysis_locked', ...)` registra cada bloqueio.

### 2. Lock por log em AIController (ajaxAnalyzeLog)

- **Problema:** Botão manual "Analisar agora" não tinha proteção contra cron simultâneo.
- **Correção:** Mesmo padrão de `realpath()` + `flock(LOCK_EX | LOCK_NB)` em `ajaxAnalyzeLog()`. Retorna `{error: 'analysis_running'}` quando lock está ocupado. `try/finally` garante liberação.

### 3. hooks.php: _locked_out

- **Problema:** `ai_last_run` era atualizado mesmo quando análise não executou por causa de lock.
- **Correção:** `if (!isset($result['_locked_out']))` antes de atualizar `ai_last_run`. Se todos os logs bloqueados, próximo cron tenta em 4min em vez de esperar `ai_interval_minutes`.

### 4. ENUM da coluna action (migration v7)

- **Problema:** ENUM `'ban','unban','manual_ban','manual_unban'` não incluía ações de auto-criação nem `analysis_locked`. `logEvent()` falhava silenciosamente para `jail_created`, `auto_filter_fallback`, `auto_filter_error`, `auto_filter_dedup`, `auto_filter_orphan`, `auto_filter_orphan_cleanup_failed`, `analysis_locked`.
- **Correção:** Migration v7 expande ENUM para 11 valores. `install.sql` atualizado.

### 5. Bug C: $allLocked no lugar errado (encontrado em teste empírico)

- **Problema:** `$allLocked = false` estava após o pre-filter. Quando um log tinha conteúdo novo, lock era adquirido, mas pre-filter removia todas as linhas, `$allLocked` permanecia `true` — falso `_locked_out`.
- **Correção:** `$allLocked = false` movido para logo após `acquireLogLock()` retornar não-null.

### 6. Bug B: logEvent com 4 argumentos (encontrado em teste empírico)

- **Problema:** `Database::logEvent()` exige 5 argumentos. Chamada em `runAnalysis()` passava apenas 4, causando `TypeError` que era capturada pelo catch silencioso.
- **Correção:** Adicionado `null` como 5º argumento (`$adminId`).

### Arquivos modificados

| Arquivo | Mudanças |
|---|---|
| `lib/AutoBanEngine.php` | `acquireLogLock()` + lock por log no loop + `$allLocked` + `_locked_out` + `is_readable()` antes do lock |
| `controllers/AIController.php` | Lock `flock(LOCK_EX \| LOCK_NB)` em `ajaxAnalyzeLog()` + `try/finally` |
| `hooks.php` | `ai_last_run` só atualiza quando `!_locked_out` |
| `amssoft_fail2ban.php` | Migration v7: expande ENUM da coluna action |
| `sql/install.sql` | ENUM expandido no schema de referência |

### Testes empíricos realizados

| Cenário | Resultado |
|---|---|
| 1 log locked + cron (disputa forçada) | ✅ `analysis_locked` registrado, outros logs processados, `ai_last_run` atualizado |
| Todos os logs locked | ✅ `_locked_out` retornado, `ai_last_run` NÃO atualizado |
| Nenhum conteúdo novo | ✅ `ai_last_run` atualizado normalmente |
| Conteúdo novo, pre-filter remove tudo | ✅ `ai_last_run` atualizado (sem falso `_locked_out`) |
| Migration v7 idempotente | ✅ 2 execuções sem erro |

---

## 2026-07-03 — Correções pós-auditoria do pipeline de IA

Auditoria completa do fluxo de criação de filtro/jail identificou 4 gaps. Corrigidos:

### 1. Auto flow: dedup por similaridade (Alta)

- **Problema:** `AutoBanEngine::autoCreateFilterAndBan()` só verificava `filterExists()` por nome exato. Se a IA gerasse `apache-probe` mas já existisse `apache-scan` com failregex similar, criava filtro duplicado.
- **Correção:** Adicionada chamada a `findSimilarFilter()` antes de `createFilter()` no fluxo automático.
- **Threshold 0.65** (maior que o 0.5 do fluxo manual) — sem humano revisando, exige mais certeza.
- **Log completo:** `auto_filter_dedup` inclui ambos failregex (sugerido + existente) para auditoria.
- **`findSimilarFilter()` atualizado:** agora retorna também o `failregex` do filtro existente (necessário para o log).

### 2. Botão manual: allowlist de logpath (Alta)

- **Problema:** `AIController::detectLogPath()` não tinha allowlist nem `attackMatchesLog()`. Botão manual "Criar Filtro" podia criar jail com logpath não validado.
- **Correção:** `detectLogPathSafe()`, `detectLogPath()`, `attackMatchesLog()` e `ALLOWED_LOGS` movidos de `AutoBanEngine` para `FilterManager` (classe compartilhada).
- Ambos os fluxos (manual e automático) agora usam `$filterManager->detectLogPathSafe()`.
- Se retornar `null`, o botão manual retorna erro claro ao admin (antes: criava jail com log errado).
- **Métodos removidos:** `AIController::detectLogPath()`, `AutoBanEngine::detectLogPathSafe()`, `AutoBanEngine::detectLogPath()`, `AutoBanEngine::attackMatchesLog()`, `AutoBanEngine::ALLOWED_LOGS`.

### 3. Filtro órfão: limpeza + log diferenciado (Média)

- **Problema:** `createFilter()` ✅ → `createJailForFilter()` ❌ = filtro órfão no disco. Loop de tentativas a cada detecção.
- **Correção:** Quando `createJailForFilter()` ou `detectLogPathSafe()` falham após filtro criado na mesma chamada, `removeFilter()` limpa o órfão.
- **Novo método:** `FilterManager::removeFilter()` — remove arquivo `.conf`, idempotente.
- **Logs diferenciados:**
  - `auto_filter_orphan` — órfão limpo com sucesso
  - `auto_filter_orphan_cleanup_failed` — falha ao remover (permissão)
- Mesmo tratamento aplicado quando `detectLogPathSafe()` retorna `null`.

### 4. Reset diário do contador (Baixa)

- **Problema:** `AutoBanEngine.php` faz read-then-write para reset do contador diário. Race condition de baixo impacto.
- **Correção:** Documentado como edge case aceitável (comentário inline). Cron roda a cada 4 min, colisão improvável. Impacto: limite excedido em 1 jail.

### Arquivos modificados

| Arquivo | Mudanças |
|---|---|
| `lib/FilterManager.php` | `findSimilarFilter()` retorna `failregex`; novos `detectLogPathSafe()`, `detectLogPath()`, `attackMatchesLog()`, `removeFilter()`, `ALLOWED_LOGS` |
| `lib/AutoBanEngine.php` | Dedup similaridade 0.65 no auto flow; usa `$filterManager->detectLogPathSafe()`; limpeza de órfão; removidos 4 métodos + constante duplicados |
| `controllers/AIController.php` | `detectLogPath()` → `$filterManager->detectLogPathSafe()`; método privado removido |

---

## 2026-07-03 — Eliminação de proliferação de filtros/jails + auto-criação

### Limpeza de filtros orfãos

- 32 filtros `amsfb-*.conf` deletados de `/etc/fail2ban/filter.d/` (backup em `/tmp/amsfb_filters_backup/`)
- 402 referências órfãs limpas no banco (`filter_name`, `failregex`, `filter_created_at`)
- 0 jails `amsfb-*` em `jail.local`, `jail.d/`, ou daemon em memória

### Prompt da IA — deduplicação de filter_name

- **DEFAULT_PROMPT atualizado:** instrução explícita para nomear por TIPO de ataque (não por IP), com exemplos: `apache-scan`, `wordpress-probe`, `rce-injection`, `cart-injection`, etc.
- **Filtros existentes no prompt:** novo método `AIAnalyzer::getExistingFilterNames()` coleta nomes do banco + disco (limitado a 30) e injeta no system prompt. IA reusa `filter_name` existente quando o ataque é do mesmo tipo.
- **`generateFilterRegex()` atualizado:** mesmo contexto de filtros existentes.

### Deduplicação por similaridade (modo sugestão)

- **`FilterManager::findSimilarFilter()`:** normaliza failregex (remove `<HOST>`, escapes, delimitadores), extrai tokens, calcula similaridade Jaccard. Threshold: 50%.
- **`FilterManager::tokenizeFailregex()`:** normalização para comparação de tokens.
- **`AIController::ajaxCreateFilter()`:** verifica similaridade antes de criar. Se similar encontrado, retorna `similar_to` + `similarity` para o frontend. Admin decide: cancelar (usar existente) ou criar novo com `force=1`.
- **Frontend (ai_suggestions.tpl):** handlers para `similar_to` em ambos os fluxos (estático e dinâmico). Confirmação com % de similaridade.
- **Log de deduplicação:** `ai_filter_dedup_log` registra decisões.

### Auto-criação de filtro/jail (modo Threshold)

- **Gate por ocorrências (Opção D):** não depende do `ai_mode`. Gate duplo: `occurrences >= min_occurrences` E `distinct_ips >= 2` dentro de uma janela de tempo.
- **`Database::analyzeFilterNameOccurrences()`:** conta ocorrências (excluindo `rejected`), IPs distintos, seleciona `best_failregex` (mais frequente).
- **`AutoBanEngine::executeBan()`:** quando `ai_auto_create_filter=1` e gate atingido, chama `autoCreateFilterAndBan()`.
- **`AutoBanEngine::autoCreateFilterAndBan()`:** cria filtro + jail via `FilterManager` (mesma rota do botão manual), bane na jail específica.
- **`AutoBanEngine::detectLogPathSafe()`:** valida contra allowlist de 7 logs. Fallback inteligente: `attackMatchesLog()` verifica se o tipo de ataque faz sentido para o log (evita jail Apache monitorando whmcs_auth.log).
- **Contador atômico:** `Database::incrementConfig()` — `UPDATE value = value + 1` (evita TOCTOU).
- **Log via `logEvent()`:** eventos `jail_created`, `auto_filter_fallback`, `auto_filter_error` — não sobrescrevem (INSERT, não setConfig).
- **TOCTOU em `createJailForFilter()`:** re-check `jailExists()` após `addJail()` falhar (corrige corrida entre processos paralelos).
- **Badge no dashboard:** `DashboardController` carrega `countAutoCreatedJailsToday()` + `getRecentAutoCreatedJails()`. Dashboard mostra alerta "N jail(s) auto-criado(s) hoje" com lista de detalhes.

### Configurações novas

| Chave | Default | Descrição |
|---|---|---|
| `ai_auto_create_filter` | `0` | Ativar auto-criação de filtro/jail |
| `ai_auto_create_min_occurrences` | `3` | Ocorrências mínimas do padrão antes de criar |
| `ai_auto_create_window_days` | `30` | Janela de tempo (dias) |
| `ai_auto_max_jails_per_day` | `5` | Limite diário de jails auto-criadas |

### Correção de encoding do prompt

- **Bug:** `persistSettings()` salvava prompt com HTML entities do formulário (`$e()` = `htmlspecialchars`). Cada salvamento double-encode: `"` → `&quot;` → `&amp;quot;`.
- **Correção:** `html_entity_decode()` antes de salvar.
- **Prompt corrigido no banco:** `&amp;amp;lt;HOST&amp;amp;gt;` → `<HOST>`, `&amp;amp;quot;` → `"`.
- **Resultado:** IA passou a retornar `filter_name` e `failregex` (antes: todos null).

### Arquivos modificados

| Arquivo | Mudanças |
|---|---|
| `lib/AIAnalyzer.php` | Prompt melhorado + `getExistingFilterNames()` + filtros no prompt |
| `lib/FilterManager.php` | `findSimilarFilter()` + `tokenizeFailregex()` + TOCTOU fix em `createJailForFilter()` |
| `lib/Database.php` | `incrementConfig()` + `analyzeFilterNameOccurrences()` + `countAutoCreatedJailsToday()` + `getRecentAutoCreatedJails()` |
| `lib/AutoBanEngine.php` | Gate por ocorrências + `autoCreateFilterAndBan()` + `detectLogPathSafe()` + `flock` por filter_name |
| `lib/AutoBanEngine.php` | `executeBan()` com gate por ocorrências + `autoCreateFilterAndBan()` + `detectLogPathSafe()` + `attackMatchesLog()` |
| `controllers/AIController.php` | `showSettings()` + `persistSettings()` + encoding fix + similaridade em `ajaxCreateFilter()` |
| `controllers/DashboardController.php` | Carrega auto_jails_today + auto_jails_recent |
| `templates/ai_settings.tpl` | Checkbox auto-create + min_occurrences + window_days + max_jails + JS toggle |
| `templates/ai_suggestions.tpl` | Handlers para `similar_to` + reenvio `force=1` |
| `templates/dashboard.tpl` | Badge de jails auto-criados hoje |

---

## 2026-07-01 — Bugs críticos de watermark (commit único)

Três bugs causavam perda silenciosa de dados de log:

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

## 2026-07-01 — Bugs de CSRF e carregamento

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

## 2026-06-30 — Observação de produção

`whmcs_auth.log` estava com watermark=3884818 mas arquivo=0 bytes — instância real do edge case de rotação (logrotate copytruncate). O próximo `analyze_log` resetou o offset para 0 e reanalisou do início (comportamento correto).
