# Critérios de aceite

Data da validação: 2026-09-12.

Este documento registra o aceite técnico da implementação planejada para a primeira release do KeySrc. Ele não substitui smoke tests manuais dos artefatos empacotados para cada sistema operacional antes da publicação de uma release no GitHub.

## Matriz de aceite

| Critério | Status | Evidência |
| --- | --- | --- |
| Uma pessoa consegue clonar o repositório, instalar dependências, executar a aplicação e criar o próprio cofre sem configuração manual. | Aprovado | `README.md` documenta clone, dependências, `go mod vendor` e `go run -mod=vendor ./cmd/keysrc`. |
| O primeiro acesso cria um cofre local. | Aprovado | Testes de UI e integração cobrem tela de cadastro inicial e criação do cofre. |
| O login desbloqueia apenas com a senha mestra correta. | Aprovado | Testes de autenticação, integração e UI cobrem senha correta e rejeição de senha incorreta. |
| A lista, cadastro/edição de credenciais e troca de senha funcionam. | Aprovado | Testes de serviço e integração cobrem CRUD de credenciais, listagem e troca de senha mestra. |
| O SQLite não contém segredos em texto claro. | Aprovado | Teste de segurança inspeciona `keysrc.sqlite3`, WAL e SHM buscando título, usuário, senha, URL, notas e tags em claro. |
| A troca de senha mestra não perde credenciais. | Aprovado | Teste de integração troca a senha, rejeita a senha antiga e lê credencial preservada com a senha nova. |
| Os testes unitários e de integração passam. | Aprovado | `go test -mod=vendor ./...` passou. |
| `go test -race` passa nos pacotes relevantes. | Aprovado | `go test -race -mod=vendor ./...` passou. |
| `govulncheck` não reporta vulnerabilidades sem tratamento. | Aprovado | `govulncheck ./...` reportou `No vulnerabilities found` para o código chamado. |
| O README documenta uso, build, modelo de segurança e limites. | Aprovado | `README.md`, `docs/modelo-de-seguranca.md` e `docs/build-e-distribuicao.md` cobrem esses pontos. |

## Comandos executados

```sh
go test -mod=vendor ./...
go test -race -mod=vendor ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.0 run --timeout=5m
go run honnef.co/go/tools/cmd/staticcheck@latest ./...
go build -mod=vendor -o bin/keysrc ./cmd/keysrc
```

## Resultado

Todos os critérios automatizáveis da fase 10 foram atendidos. Antes de publicar uma release, execute o checklist em `docs/checklist-release.md`, gere os pacotes por plataforma e faça smoke test manual em cada artefato publicado.
