## Resumo

- 

## Tipo de mudança

- [ ] Correção
- [ ] Funcionalidade
- [ ] Refatoração
- [ ] Documentação
- [ ] Build/CI/dependências
- [ ] Segurança

## Validação

- [ ] `go test -mod=vendor ./...`
- [ ] `go test -race -mod=vendor ./...`
- [ ] `govulncheck ./...`
- [ ] `golangci-lint run`
- [ ] Não aplicável; motivo:

## Checklist de segurança

Obrigatório para PRs que toquem autenticação, criptografia, storage, permissões, clipboard, logs, UI de segredos, dependências ou empacotamento.

- [ ] Revisei `docs/checklist-seguranca-pr.md`.
- [ ] O PR não registra nem persiste segredos em texto claro.
- [ ] O PR usa `crypto/rand` para aleatoriedade sensível.
- [ ] O PR preserva nonce único por operação de cifragem.
- [ ] O PR trata falha de autenticação criptográfica como falha segura.
- [ ] O PR não enfraquece Argon2id, política de senha mestra ou limites documentados sem justificativa.
- [ ] O PR inclui testes de sucesso e falha para o comportamento alterado.
- [ ] O PR atualiza documentação quando altera comportamento de segurança.
- [ ] Não aplicável; motivo:

## Observações

- 
