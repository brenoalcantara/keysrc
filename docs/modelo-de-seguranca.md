# Modelo de seguranca

O KeySrc é um cofre local. Ele protege dados em repouso no SQLite contra leitura casual, vazamento acidental em logs e roubo do arquivo de banco sem a senha mestra.

## O que é protegido?

- Senhas de credenciais.
- Usuarios, URLs, titulos, notas e tags salvos nas credenciais.
- Chave do cofre, que fica cifrada em repouso.
- Metadados sensíveis contra alteração não autenticada, quando usados como AAD da cifra.

## Fluxo criptográfico

No primeiro acesso:

1. A aplicação gera uma chave aleatória de 32 bytes para o cofre.
2. A senha mestra é processada com Argon2id.
3. HKDF deriva subchaves com contexto explícito.
4. A chave do cofre é cifrada com XChaCha20-Poly1305.
5. O banco salva apenas salt, parametros KDF, verificador, nonce e chave do cofre cifrada.

Ao salvar credenciais:

1. A credencial é serializada em memória.
2. A aplicação gera um nonce aleatório.
3. O payload é cifrado com XChaCha20-Poly1305.
4. O SQLite recebe somente ciphertext, nonce e metadados mínimos.

Na troca de senha mestra, a aplicação valida a senha atual, abre a chave do cofre e recifra apenas essa chave com subchaves derivadas da nova senha.

## Senha mestra

A senha mestra não é armazenada e não existe recuperação. Se ela for perdida, o cofre deve ser considerado irrecuperável.

Use uma senha longa e exclusiva. O projeto aplica política mínima de senha, mas a qualidade final depende da escolha do usuário.

## Limites

O KeySrc não oferece proteção completa contra:

- Sistema operacional comprometido.
- Malware ou keylogger.
- Processo com permissão para ler memória da aplicação.
- Usuário deixando a sessao desbloqueada.
- Clipboard monitorado por outro processo.
- Captura de tela.
- Backups externos inseguros.
- Perda da senha mestra.

## Clipboard e memória

A aplicação tenta limpar o clipboard após copiar segredos, desde que o conteúdo ainda seja o mesmo copiado pelo KeySrc. Essa limpeza é uma reduçao de risco, não uma garantia absoluta.

Dados descriptografados existem em memória enquanto o cofre está desbloqueado. O bloqueio manual, o bloqueio por inatividade e a limpeza de campos reduzem o tempo de exposição.

## Arquivos locais

O banco fica no diretório de configuração do usuário, em `keysrc/keysrc.sqlite3`. O projeto aplica permissões restritivas ao banco e aos arquivos auxiliares do SQLite quando o sistema operacional permite.

Arquivos `*.sqlite`, `*.sqlite3`, `*.db`, WAL e SHM não devem ser commitados.

## Regras para alteracoes futuras

- Nunca registrar senhas, usuários, URLs, notas ou payloads descriptografados em logs.
- Nunca persistir texto claro no SQLite.
- Usar `crypto/rand` para todo nonce, salt, token ou senha gerada.
- Tratar falha de autenticação criptográfica como falha segura.
- Manter testes para senha errada, nonce errado, AAD errado e ciphertext adulterado.
- Rodar `go test -race` e `govulncheck` antes de releases.
