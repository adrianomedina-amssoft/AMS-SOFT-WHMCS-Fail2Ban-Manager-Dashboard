# Segurança e dados sensíveis

## O que não publicar

- `configuration.php` do WHMCS, `.env`, credenciais de banco, chaves de API, tokens, cookies ou chaves privadas.
- Dumps SQL, bancos de runtime, backups, logs reais, listas de IPs de clientes e manifests de manutenção.
- PRDs de ambiente, inventários internos, instruções de acesso ou capturas de telas administrativas reais.

Credenciais criptografadas também são dados sensíveis e não devem ser publicadas. Um teste deve usar valores claramente fictícios, não uma cópia de produção.

## Antes de cada push

1. Prepare a publicação fora da instalação ativa e copie apenas código, exemplos e testes revisados.
2. Revise `git status`, `git diff --cached --name-status` e o conteúdo integral do commit. Arquivos já rastreados não são protegidos pelo `.gitignore`.
3. Verifique texto, comentários, fixtures, imagens, URLs, endereços e IDs de ambiente. Use domínios `.invalid` e redes de documentação para exemplos.
4. Execute uma ferramenta de detecção de segredos no diretório e nos commits que serão enviados, com saída redigida. Revise os candidatos manualmente; ausência de alertas não prova ausência absoluta de dados sensíveis.
5. Rode os testes apropriados em ambiente isolado. Não inclua os relatórios privados produzidos pela verificação.
6. Confira destino, branch e histórico. Não envie commits privados apenas porque o arquivo sensível foi removido no commit mais recente.

As capturas e instruções internas presentes em versões antigas foram retiradas da árvore atual. O histórico não foi reescrito; cópias históricas podem continuar acessíveis. Apagar o arquivo atual não revoga credenciais nem remove cópias de terceiros.

## Em caso de exposição

Revogue/rotacione primeiro as credenciais afetadas e avalie o impacto. A limpeza de histórico é uma operação separada, coordenada com o mantenedor e colaboradores; não deve ser feita por force push improvisado. Nunca cole um segredo em issue, comentário ou relatório público para demonstrar a exposição.

Relatos públicos devem conter apenas passos reproduzíveis e dados sintéticos. Para uma vulnerabilidade sensível, procure um canal privado do mantenedor antes de divulgar detalhes; não há garantia de prazo de resposta.

## Dados enviados à IA

As evidências selecionadas podem conter IPs, URLs e conteúdo de logs. Configure coleta, fornecedor e retenção conforme as obrigações da sua organização. Exclusão de IPs cobertos reduz chamadas, mas não equivale a anonimização universal do conteúdo enviado.
