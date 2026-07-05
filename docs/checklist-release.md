# Checklist de release

Use este checklist antes de publicar uma versão do KeySrc.

## Preparação

- Atualizar `README.md` e documentos em `docs/`.
- Confirmar versão do Go em `go.mod`.
- Recriar dependências locais com `go mod tidy` e `go mod vendor`.
- Conferir que `vendor/`, bancos locais, binários e arquivos temporários continuam ignorados.
- Conferir que `vibe/` continua ignorada.

## Qualidade

```sh
go test -mod=vendor ./...
go test -race -mod=vendor ./...
govulncheck ./...
```

- Executar lint pelo CI ou localmente com `golangci-lint run`.
- Revisar falhas, warnings e vulnerabilidades antes de empacotar.
- Confirmar que o workflow do GitHub Actions passou na branch ou tag da release.

## Seguranca

- Criar um cofre novo e validar primeiro acesso.
- Fazer login com senha correta.
- Confirmar rejeicao de senha incorreta.
- Criar, editar, buscar e excluir uma credencial.
- Trocar senha mestra e confirmar que a senha antiga falha.
- Conferir que as credenciais continuam disponíveis após a troca.
- Inspecionar o SQLite e confirmar que título, usuário, senha, URL e notas não aparecem em texto claro.
- Validar bloqueio manual e bloqueio por inatividade.
- Testar limpeza de clipboard após copiar usuário ou senha.

## Build

- Gerar binario local com `go build -mod=vendor -o bin/keysrc ./cmd/keysrc`.
- Gerar pacote Fyne para cada plataforma suportada.
- Executar smoke test em cada pacote gerado.
- Conferir que o app cria o banco no diretório de configuração do usuário.
- Conferir que o app nao exige configuração manual no primeiro acesso.

## Publicação

- Criar tag assinada quando possível.
- Publicar release no GitHub com artefatos e checksums.
- Registrar sistemas operacionais testados.
- Declarar limites de segurança nas notas da release.
- Informar que a senha mestra perdida não pode ser recuperada.
