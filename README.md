# KeySrc

Projeto pessoal de cofre de senhas desktop.

## Tecnologias

- Go 1.26.2
- Fyne v2.7.3
- SQLite

## Desenvolvimento

Se o Go nao estiver no `PATH`, use o binario diretamente:

```sh
/usr/local/go/bin/go version
```

Baixe as dependencias e salve uma copia local em `vendor/`:

```sh
go mod tidy
go mod vendor
```

Execute usando as dependencias locais:

```sh
go run -mod=vendor ./cmd/keysrc
```

Gere um binario local:

```sh
go build -mod=vendor -o bin/keysrc ./cmd/keysrc
```

## Observacao sobre dependencias

A pasta `vendor/` e ignorada pelo Git neste projeto, mas pode ser recriada localmente com `go mod vendor`.
# keysrc
