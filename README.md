# KeySrc

KeySrc é um cofre de senhas desktop, local e autônomo. A aplicação permite criar o cofre no primeiro acesso, desbloquear com senha mestra, cadastrar credenciais, buscar registros, copiar dados quando necessário e trocar a senha mestra sem recifrar todas as credenciais.

## Tecnologias

- Go 1.26.6
- Fyne v2.7.3
- SQLite com `modernc.org/sqlite`
- Argon2id, HKDF e XChaCha20-Poly1305

## Modelo de segurança

O banco SQLite é tratado como armazenamento de blobs cifrados. A senha mestra nunca é salva. No primeiro acesso, o KeySrc gera uma chave aleatória do cofre, deriva subchaves com Argon2id/HKDF e salva somente metadados de derivação, verificador criptográfico e a chave do cofre cifrada.

Credenciais são cifradas antes de serem persistidas. O arquivo SQLite não deve conter título, usuário, senha, URL ou notas em texto claro. Se a senha mestra for perdida, o cofre não pode ser recuperado.

Limites importantes:

- O KeySrc não protege contra sistema operacional comprometido, malware, keylogger ou processo com permissão para ler memória da aplicação.
- Clipboard, captura de tela, backups externos e sessão desbloqueada continuam sendo superfícies de risco.
- A aplicação reduz exposição acidental, mas não substitui higiene operacional do dispositivo.

Detalhes estão em [docs/modelo-de-seguranca.md](docs/modelo-de-seguranca.md).

## Instalacao para desenvolvimento

Clone o repositório e entre no diretório:

```sh
git clone git@github.com:brenoalcantara/keysrc.git
cd keysrc
```

Se o Go nao estiver no `PATH`, use o binário diretamente:

```sh
/usr/local/go/bin/go version
```

No Linux, instale também as dependências gráficas usadas por aplicações Fyne:

```sh
sudo apt-get update
sudo apt-get install -y gcc libgl1-mesa-dev xorg-dev
```

Baixe as dependências e salve uma cópia local em `vendor/`:

```sh
go mod tidy
go mod vendor
```

Execute usando as dependências locais:

```sh
go run -mod=vendor ./cmd/keysrc
```

## Testes e verificacoes

Execute a suíte principal:

```sh
go test -mod=vendor ./...
```

Execute testes com detector de corrida:

```sh
go test -race -mod=vendor ./...
```

Rode verificação de vulnerabilidades:

```sh
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

## Build

Gere um binário local:

```sh
go build -mod=vendor -o bin/keysrc ./cmd/keysrc
```

Se o ambiente local nao permitir carimbo de VCS durante o build, use:

```sh
go build -buildvcs=false -mod=vendor -o bin/keysrc ./cmd/keysrc
```

Para empacotar com a ferramenta oficial do Fyne:

```sh
go install fyne.io/tools/cmd/fyne@latest
fyne package -os linux -icon assets/icon.png
fyne package -os windows -icon assets/icon.png
fyne package -os darwin -icon assets/icon.png
```

Crie `assets/icon.png` antes de empacotar uma release. Detalhes e notas por plataforma estão em [docs/build-e-distribuicao.md](docs/build-e-distribuicao.md).

## Dados locais

O arquivo do cofre fica no diretório de configuração do usuário, em um subdiretório `keysrc`, usando o caminho retornado por `os.UserConfigDir()`. Em Linux, isso normalmente fica em `$XDG_CONFIG_HOME/keysrc/keysrc.sqlite3` ou `$HOME/.config/keysrc/keysrc.sqlite3`.

Arquivos SQLite auxiliares, como WAL e SHM, também devem receber permissão restritiva quando o sistema operacional permitir.

## CI e release

O workflow em `.github/workflows/ci.yml` executa testes, `go test -race`, build, lint com `golangci-lint` e `govulncheck`.

Antes de publicar uma versão, siga [docs/checklist-release.md](docs/checklist-release.md).

## Dependencias locais

A pasta `vendor/` é ignorada pelo Git neste projeto, mas pode ser recriada localmente com `go mod vendor`.
