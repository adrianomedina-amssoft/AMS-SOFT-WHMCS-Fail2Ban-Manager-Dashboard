# Changelog público

## 2.2.58

- Grupo nativo opcional `boaform_probe`, com GET e caminho literal restritos, seleção pela UI, whitelist e controles compartilhados. Uma ocorrência quando configurado com Tentativas = 1; desativado por padrão em novas instalações.
- Revisitação de campanhas limitada à atividade recente, tarefa própria e prova validada. Tarefas de outros buckets não emprestam autoridade; comparação de estado preserva revisões, proteção e backoff.
- Estado pending/retry coerente para tarefas reabertas e contagem apenas após atualização efetiva.
- Testes de assinatura, negativos, IPv4/IPv6 e revisitação de dois buckets do mesmo IP. Reconciliações operacionais e identificadores de instalação não são distribuídos.

## 2.2.57

- Reconhecimento fechado de SQL ofuscado e precedência sobre o agrupamento genérico de sondagem PHP.
- Grupos opcionais `sql_obfuscated` e `admin_config_probe`, com controles e ajuda pela UI, preservando a regra SQL legada.
- Discriminação dos motivos de saída da memória da fila e recuperação local de adiamentos de cobertura com recência e proteção conhecida.
- Regressões de sintaxe SQL, consulta de cobertura, contadores transacionais, rollback e idempotência. Sem aumento de orçamento ou cadência da IA.

## 2.2.56

- Grupo nativo opcional `sql_injection` para sintaxes SQL fechadas nas queries de `/cart.php` e `/index.php`.
- Correlação opcional de AH02032/SNI com access421 inequívoco de rota retirada, sem whitelist por IP, status ou User-Agent.
- Ajustes na observação local conservadora e testes de correlação, identidade e opt-out. Sem configuração real do servidor ou dados operacionais no pacote.

## 2.2.55

- Novo grupo nativo opcional `session_lfi_probe`, com alvo e payload fechados, controle na UI e limites nativos existentes. Desativado por padrão em novas instalações.
- Recusa antecipada de prefixos arbitrários antes do IP em novos filtros e regressões de captura incorreta, IPv4/IPv6 e campos forjados.
- Transformação pura, de escopo finito, para revisão operacional de cabeçalhos de cinco filtros legados; aplicação não automática e sem configuração real de servidor no pacote.
- Testes de assinatura, negativos, seleção do catálogo e preservação dos padrões existentes. Nenhuma mudança de schema, confiança ou orçamento da IA.

Esta publicação contém código, testes sintéticos e documentação pública. Relatórios operacionais, PRDs, logs, identificadores reais de detecções e regras aprendidas de uma instalação permanecem privados.

## 2.2.54

Esta publicação consolida o desenvolvimento posterior à versão pública 2.0.1. O resumo abaixo descreve funcionalidades; não reproduz auditorias nem estado de servidores.

- Ponte privilegiada restrita, validação de filtros/evidências e verificação de cobertura efetiva do firewall.
- Catálogo de sondagem nativa, regras específicas e critérios comportamentais configuráveis.
- Exclusão de IPs protegidos antes da análise paga e rechecagem antes do transporte ao provedor.
- Fila incremental, memória de decisões, limites de consumo, controle de recência e telemetria de ciclos.
- Provedores de IA, tratamento de respostas e confirmação explícita para automação e ações manuais.
- Revisão dos fluxos de dashboard, IPs, jails, logs, relatórios, IA, configurações e proteção, incluindo paginação, limites e tratamento de estados desconhecidos.
- Leitura consolidada do inventário nativo para reduzir chamadas por jail.
- Separação entre janela de repetição de query e prazo de validade individual da evidência.
- Testes PHP, Python e JavaScript distribuídos com exemplos fictícios.
- Documentação de instalação revisada e regras de exclusão reforçadas para publicação pública.

Dados de runtime, credenciais, PRDs internos, backups e capturas operacionais não fazem parte desta versão. Exemplos de domínio, rotas personalizadas e diretórios específicos foram anonimizados. A atualização do código não redefine bans, regras ou configurações de uma instalação existente.

## Histórico anterior

Os commits anteriores permanecem no Git. A remoção de um arquivo da versão atual não o apaga de commits antigos; para publicação segura, consulte [SECURITY.md](SECURITY.md).
