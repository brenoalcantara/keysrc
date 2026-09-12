# Checklist de segurança para PRs

Use este checklist em qualquer PR que toque autenticação, criptografia, storage, permissões, clipboard, logs, UI de segredos, dependências ou empacotamento.

Se um item não se aplicar, marque como não aplicável no PR e explique brevemente o motivo.

## Dados sensíveis

- O PR evita salvar senha mestra, senhas de credenciais, usuários, URLs, notas, tags sensíveis ou payloads descriptografados em logs?
- O PR evita persistir texto claro no SQLite, arquivos temporários, cache, fixtures, screenshots ou artefatos de teste?
- O PR mantém campos sensíveis limpos após sucesso, erro, cancelamento, troca de tela ou bloqueio do cofre?
- O PR evita exibir senha de credencial por padrão?
- O PR não adiciona dumps de structs que possam conter segredos?

## Criptografia

- O PR usa `crypto/rand` para todo nonce, salt, chave, token ou senha gerada?
- O PR preserva nonce único por operação de cifragem?
- O PR mantém XChaCha20-Poly1305 como cifra autenticada da versão criptográfica atual?
- O PR mantém AAD vinculando dados ao contexto esperado, como versão, tabela lógica e ID do registro?
- O PR trata falha de autenticação criptográfica como falha segura?
- O PR evita retornar dados parciais quando descriptografia, verificação de AAD ou validação do cofre falha?

## Senha mestra e KDF

- O PR não enfraquece os parâmetros de Argon2id sem justificativa medida e documentada?
- O PR preserva a política mínima da senha mestra ou documenta explicitamente qualquer alteração?
- O PR não adiciona recuperação de senha mestra nem caminho que permita ignorar autenticação?
- O PR mantém troca de senha mestra recifrando apenas a chave do cofre, salvo migração criptográfica planejada?
- O PR preserva a impossibilidade de abrir o cofre com senha antiga após troca bem-sucedida?

## Storage e transações

- O PR usa transações para operações que precisam ser atômicas, como criação do cofre e troca de senha mestra?
- O PR mantém permissões restritivas no banco SQLite e arquivos auxiliares quando o sistema operacional permite?
- O PR não cria novos arquivos de dados sensíveis fora do diretório de configuração do usuário?
- O PR mantém bancos locais, WAL, SHM, binários, `vendor/`, `vibe/` e arquivos temporários fora do Git?
- O PR trata corrupção, registro inexistente e dados adulterados como falha controlada?

## Clipboard, UI e sessão

- O PR copia usuário ou senha para clipboard apenas por ação explícita do usuário?
- O PR mantém ou melhora a limpeza posterior do clipboard sem apagar conteúdo novo do usuário?
- O PR preserva bloqueio manual e bloqueio por inatividade?
- O PR garante que bloquear o cofre limpa sessão, clipboard rastreado e caches em memória quando possível?
- O PR não introduz telas que exponham segredos mais do que o fluxo exige?

## Dependências e build

- O PR não adiciona dependência criptográfica, storage ou GUI abandonada ou desnecessária?
- O PR roda `govulncheck` quando altera dependências, toolchain, build, rede, storage ou criptografia?
- O PR atualiza `go.mod`, `go.sum` e `vendor/` localmente quando muda dependências?
- O PR mantém `.gitignore`, CI e documentação coerentes com os artefatos gerados?

## Testes obrigatórios quando aplicável

- O PR inclui testes de sucesso e falha?
- O PR cobre senha errada, nonce errado, AAD errado ou ciphertext adulterado quando altera criptografia?
- O PR cobre persistência sem texto claro quando altera serialização, storage ou payload de credenciais?
- O PR cobre troca de senha preservando credenciais quando altera autenticação, KDF ou metadados do cofre?
- O PR cobre fluxo de UI quando altera telas de login, cadastro, credenciais, troca de senha ou bloqueio?
- O PR passa em `go test -mod=vendor ./...`.
- O PR passa em `go test -race -mod=vendor ./...` quando toca concorrência, sessão, UI assíncrona, clipboard ou storage.

## Documentação

- O PR atualiza `README.md`, `docs/modelo-de-seguranca.md`, `docs/decisoes-tecnicas.md` ou `docs/build-e-distribuicao.md` quando altera comportamento de segurança, build, release ou plataforma suportada?
- O PR documenta novas limitações de segurança conhecidas?
- O PR atualiza checklist de release quando muda o processo de publicação?
