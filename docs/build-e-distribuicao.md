# Build e distribuicao

Este documento descreve como executar, testar, compilar e preparar pacotes do KeySrc.

## Requisitos

- Go 1.26.6.
- Dependências do Fyne para a plataforma alvo.
- SQLite via `modernc.org/sqlite`, sem dependência direta de uma biblioteca SQLite do sistema.
- Uma cópia local de dependências em `vendor/`, quando a preferência for build reproduzível localmente.

No Linux Debian/Ubuntu:

```sh
sudo apt-get update
sudo apt-get install -y gcc libgl1-mesa-dev xorg-dev
```

No macOS, instale o Go e as ferramentas de linha de comando do Xcode. No Windows, instale o Go e uma toolchain C compatível com Fyne. Para a primeira release, prefira gerar o pacote no próprio sistema operacional alvo.

## Dependências locais

```sh
go mod tidy
go mod vendor
```

A pasta `vendor/` fica fora do Git por escolha do projeto, mas os comandos de desenvolvimento e CI podem recriá-la.

## Execucao em desenvolvimento

```sh
go run -mod=vendor ./cmd/keysrc
```

## Testes

```sh
go test -mod=vendor ./...
go test -race -mod=vendor ./...
```

Verificação de vulnerabilidades:

```sh
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

## Build local

```sh
go build -mod=vendor -o bin/keysrc ./cmd/keysrc
```

Se o ambiente nao permitir informações de VCS no binário:

```sh
go build -buildvcs=false -mod=vendor -o bin/keysrc ./cmd/keysrc
```

## Pacotes com Fyne

Instale a ferramenta oficial:

```sh
go install fyne.io/tools/cmd/fyne@latest
```

Crie um ícone em `assets/icon.png` antes de empacotar. Exemplos:

```sh
fyne package -os linux -icon assets/icon.png
fyne package -os windows -icon assets/icon.png
fyne package -os darwin -icon assets/icon.png
```

Para evitar falsas expectativas de release, trate os pacotes de Windows e macOS como suportados apenas depois de um smoke test no sistema correspondente. Cross-build pode ser adicionado depois com uma pipeline específica e validada.

## Artefatos sugeridos

- Linux: `keysrc-linux-amd64.tar.xz` ou pacote nativo gerado pelo Fyne.
- Windows: `keysrc-windows-amd64.zip` contendo `keysrc.exe`.
- macOS: `KeySrc.app` compactado e assinado quando houver processo de assinatura.

## Checklist curta de build

- Recriar `vendor/`.
- Rodar testes e race tests.
- Rodar `govulncheck`.
- Gerar binário.
- Empacotar com Fyne.
- Executar smoke test em uma conta de usuário limpa.
- Conferir que o SQLite criado não contém segredos em texto claro.
