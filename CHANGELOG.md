# Changelog público

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
