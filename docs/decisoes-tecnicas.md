# Decisões técnicas

Data da confirmação: 2026-09-12.

Este documento fecha as decisões que ficaram pendentes no plano de implementação. Mudanças futuras que alterem criptografia, armazenamento, política de senha, bloqueio ou plataformas suportadas devem atualizar este documento e incluir migração/testes quando aplicável.

## Resumo

| Tema | Decisão |
| --- | --- |
| Driver SQLite | `modernc.org/sqlite`. |
| Cifra autenticada | XChaCha20-Poly1305. |
| Argon2id | 64 MiB, 3 iterações, paralelismo de `runtime.NumCPU()` limitado a 4, salt de 16 bytes e chave de 32 bytes. |
| Bloqueio por inatividade | 5 minutos. |
| Limpeza de clipboard | 45 segundos, limpando apenas se o conteúdo ainda for o valor copiado pelo KeySrc. |
| Política de senha mestra | Mínimo de 14 caracteres, com minúscula, maiúscula, dígito e símbolo. |
| Plataformas da primeira release | Linux como plataforma primária; Windows e macOS somente após smoke test no sistema correspondente. |

## SQLite

Decisão: manter `modernc.org/sqlite`.

Motivos:

- Evita dependência direta de CGO para o driver SQLite.
- Simplifica distribuição desktop.
- O modelo criptográfico do projeto cifra os dados na aplicação, então o SQLite é usado como armazenamento de blobs cifrados e metadados mínimos.

Consequência: se no futuro houver troca para `github.com/mattn/go-sqlite3`, ela deve ser justificada por necessidade nativa específica, revisada na distribuição multiplataforma e validada com os testes de storage e segurança.

## Criptografia

Decisão: manter XChaCha20-Poly1305 via `golang.org/x/crypto/chacha20poly1305`.

Motivos:

- Nonce de 24 bytes reduz risco operacional de colisão quando nonces são aleatórios.
- API simples com chave de 32 bytes.
- AAD já vincula registros ao contexto lógico, versão e identificador da credencial.

Consequência: `CryptoVersion = 1` representa este formato. Qualquer troca futura de cifra ou AAD exige nova versão criptográfica e plano de migração.

## Argon2id

Decisão: manter os parâmetros padrão atuais:

- Memória: 64 MiB.
- Iterações: 3.
- Paralelismo: número de CPUs limitado a 4.
- Salt: 16 bytes.
- Saída: 32 bytes.

Esses valores são conservadores para desktop e preservam um custo perceptível para tentativa de senha, sem tornar a experiência inviável para uso local. Para evitar regressão silenciosa, foi adicionado o benchmark manual `BenchmarkDeriveMasterKeyDefaultParams`.

Comando para medir:

```sh
go test -run '^$' -bench BenchmarkDeriveMasterKeyDefaultParams -benchtime=1x -mod=vendor ./internal/security
```

## Bloqueio e clipboard

Decisão: manter bloqueio por inatividade em 5 minutos.

Motivo: reduz exposição quando o usuário se afasta da máquina sem tornar o uso comum excessivamente interrompido.

Decisão: manter limpeza de clipboard em 45 segundos.

Motivo: dá tempo suficiente para colar usuário/senha em fluxo normal, mas reduz a janela de exposição acidental. A limpeza só acontece se o clipboard ainda tiver o conteúdo copiado pelo KeySrc, evitando apagar conteúdo posterior do usuário.

## Senha mestra

Decisão: manter a política padrão:

- Mínimo de 14 caracteres.
- Pelo menos uma letra minúscula.
- Pelo menos uma letra maiúscula.
- Pelo menos um dígito.
- Pelo menos um símbolo.

Motivo: impõe um piso prático sem tentar substituir orientação de uso. O README e o modelo de segurança continuam deixando claro que senha perdida não pode ser recuperada.

## Plataformas

Decisão: primeira release com Linux como plataforma primária de validação.

Windows e macOS permanecem como alvos de empacotamento documentados, mas só devem ser marcados como suportados em uma release depois de smoke test no sistema operacional correspondente. Cross-build pode ser adicionado depois, desde que a pipeline gere artefatos testáveis e o checklist de release seja atualizado.
