# vedei — Milestones

Plano de execução. A arquitetura está em [`ARCHITECTURE.md`](ARCHITECTURE.md).

Cada etapa tem a mesma estrutura: **objetivo** (uma frase), **o que implementar** (features numeradas), **passo a passo** (ordem de execução), **como testar** (unitário, integração, manual) e **critério de saída** (verificável, sem interpretação).

Premissa de esforço: ~10 h por semana.

**Regra de ouro:** cada milestone termina em estado publicável. Se for parar, pare depois de um, nunca no meio.

---

## Mapa

| | Milestone | Esforço | Entrega |
|---|---|---|---|
| M0 | Fundação | 1 sem | repositório utilizável |
| M1 | Núcleo BR + validação offline | 3 sem | biblioteca Go |
| M2 | Motor de segredos via betterleaks | 4 dias | dois motores, um formato |
| M3 | 🎯 **MVP** — superfície de IA | 3 sem | hook + auditoria de transcript |
| M4 | CLI, CI/CD, SARIF, scrub | 3 sem | adoção |
| M5 | Corpus multilíngue + calibração pt-BR | 3 sem | falso positivo vira métrica |
| M6 | SDK de runtime | 3 sem | prevenção |
| M7 | Camada de IA | 4 sem | triagem e geração de regra |
| M8 | Coletor de observabilidade | 5 sem | log e trace de produção |
| M9 | Validação de segredo + allowlist de destino | 2 sem | contribuição de volta |
| M10 | v1.0 | 3 sem | projeto de outros, não só seu |

---

## M0 — Fundação

**Objetivo.** Um estranho clona, builda e entende em cinco minutos.

### O que implementar

1. `go.mod` — módulo `github.com/mkmuniz/vedei`, Go 1.27
2. `LICENSE` — MIT
3. `SECURITY.md` — canal privado de divulgação; obrigatório em ferramenta de segurança
4. `CONTRIBUTING.md` — como um detector novo é aceito (regex + validador + corpus de teste)
5. `Makefile` — `build`, `test`, `lint`, `bench`, `cover`
6. CI (`.github/workflows/ci.yml`) — `go test ./...`, `go vet`, `golangci-lint`, build para linux/darwin/windows em amd64 e arm64
7. `.golangci.yaml` — com `gosec` ligado (é ferramenta de segurança; tem que passar no próprio scanner)
8. ADRs 001 a 005 em `docs/adr/` — já redigidos em `ARCHITECTURE.md` §7

### Passo a passo

1. `go mod init`
2. Escrever LICENSE, SECURITY, CONTRIBUTING
3. Esqueleto de pastas com um `doc.go` em cada pacote explicando sua responsabilidade
4. Um teste trivial que passa, só para o CI ter o que rodar
5. CI verde
6. ADRs

### Como testar

```bash
make build && make test && make lint
```

Em máquina limpa, com o repositório recém-clonado.

### Critério de saída

- [ ] CI verde no GitHub
- [ ] `make build` produz binário em máquina sem estado prévio
- [ ] `gosec` passa sem exceção suprimida
- [ ] Cada pacote tem `doc.go` dizendo o que faz

**Risco:** gastar duas semanas em bikeshedding. Timebox de uma semana, sem exceção.

---

## M1 — Núcleo BR + validação offline

**Objetivo.** Dado um texto, devolver achados de dado sensível brasileiro com veredito estrutural.

**É a etapa onde mora o valor do projeto.** Se só isso existir, o projeto já é útil como biblioteca.

### O que implementar

**1.1 — Validadores puros** (`detect/br/`, zero dependência externa)

| Função | Algoritmo | Cuidado específico |
|---|---|---|
| `ValidateCPF` | mod 11, dois DVs | rejeitar `000.000.000-00` até `999.999.999-99` (11 sequências repetidas passam no mod 11) |
| `ValidateCNPJ` | mod 11, pesos `5,4,3,2,9,8,7,6,5,4,3,2` | aceitar **numérico e alfanumérico**; letras valem `ASCII − 48` |
| `ValidateCNH` | mod 11, variante 11 dígitos | o segundo DV depende do primeiro |
| `ValidatePIS` | mod 11, pesos `3,2,9,8,7,6,5,4,3,2` | resto 10 e 11 viram 0 |
| `ValidateTituloEleitor` | dois DVs, mod 11 | dígitos 9–10 são código de UF, válido de 01 a 28 |
| `ValidateCNS` | soma ponderada ≡ 0 (mod 11) | dois formatos: começa com 1/2 (definitivo) ou 7/8/9 (provisório) |
| `ValidateLuhn` | Luhn | + faixa de BIN para bandeira |
| `ValidateChavePix` | por tipo | CPF, CNPJ, e-mail, telefone `+55` com DDD válido, EVP (UUID v4) |
| `ValidateE2EID` | estrutura | `E` + ISPB(8) + `AAAAMMDDHHMM` + 11 alfanum; data coerente; ISPB existe |

`CIN` reusa `ValidateCPF` — é o mesmo número.
`RG` **não tem validador**. Só detector contextual, sempre `ConfidenceLow`.

**1.2 — Extração** (`detect/br/extract.go`)

Regex tolerante às máscaras reais: `123.456.789-09`, `12345678909`, `123 456 789 09`, `123456789-09`.
Fronteira de palavra obrigatória, senão um CPF é encontrado dentro de um hash.

**1.3 — Base de ISPB**

Consumir [`guibranco/BancosBrasileiros`](https://github.com/guibranco/BancosBrasileiros), embutir com `go:embed` comprimido, e um `make update-ispb` que rebaixa e regenera.

**1.4 — Tipos do núcleo** (`detect/types.go`)

`Finding`, `Validity`, `Confidence`, `Location`, `Metadata` — conforme `ARCHITECTURE.md` §4.

**1.5 — Fingerprint** (`fingerprint/`)

SHA-256 de `tipo + valor normalizado`, **não** da linha. Mover o arquivo não pode invalidar o ignore.

### Passo a passo

1. `ValidateCPF` + teste. É o mais usado e ensina o padrão para os outros.
2. `ValidateCNPJ` numérico, depois alfanumérico.
3. Os demais validadores, um por vez, cada um com teste antes de passar ao próximo.
4. `extract.go` — regex por tipo.
5. Integrar extração + validação no `engine/br`.
6. Base de ISPB e `ValidateE2EID`.
7. Fingerprint.
8. Benchmarks.

### Como testar

**Unitário — teste de propriedade, não de exemplo.** Para cada validador:

```go
// 1. Gerar N validos e provar que todos passam
func TestCPF_GeradosSaoValidos(t *testing.T) {
    for i := 0; i < 100_000; i++ {
        cpf := gerarCPFValido(rand)
        require.True(t, ValidateCPF(cpf), cpf)
    }
}

// 2. Corromper um digito e provar que todos falham
func TestCPF_CorrompidoFalha(t *testing.T) { ... }

// 3. Sequencias repetidas nunca passam
func TestCPF_RepetidosFalham(t *testing.T) {
    for d := 0; d <= 9; d++ {
        require.False(t, ValidateCPF(strings.Repeat(strconv.Itoa(d), 11)))
    }
}
```

**Fuzzing** (`go test -fuzz`) em `extract.go`: entrada arbitrária não pode causar pânico nem laço infinito.

**Vetores conhecidos.** Uma tabela com valores publicamente documentados como válidos e inválidos, em `testdata/vetores.csv`.

**Benchmark.**
```bash
make bench   # alvo: > 50 MB/s de texto varrido
```

### Critério de saída

- [ ] Cobertura ≥ 90% em `detect/br`
- [ ] Zero falso positivo sobre 10.000 valores inválidos gerados, por tipo
- [ ] Fuzzing roda 5 min sem crash em `extract`
- [ ] Benchmark publicado no README
- [ ] `vedei` como biblioteca: `br.Scan([]byte("cpf 123.456.789-09"))` devolve 1 achado válido

**Risco:** tentar detecção contextual sofisticada agora. Não. Nesta etapa é regex + validador; o validador carrega o peso.

---

## M2 — Motor de segredos via betterleaks

**Objetivo.** Herdar 463 regras de segredo sem escrever nenhuma.

### O que implementar

1. `engine/secrets/` — implementa `detect.Engine` embrulhando o betterleaks
2. Tradução do achado deles para o `Finding` nosso
3. Validação de segredo **desligada** nesta etapa (`Capabilities.RequiresNetwork = false`)
4. Supressão cruzada: se os dois motores acham no mesmo intervalo, o mais específico vence

### Passo a passo

1. `go get github.com/betterleaks/betterleaks`
2. Adaptador mínimo sobre `detect.DetectString`
3. Mapear campos (`RuleID` → `Type`, `Secret` → `Raw`, `Entropy` → metadado)
4. Regra de precedência entre motores
5. Teste de integração com repositório de fixture

### Como testar

Fixture em `testdata/repo-misto/` com, no mesmo arquivo:
- um CPF válido
- um CPF inválido (não pode aparecer)
- uma chave AWS falsa mas com formato correto
- um CPF dentro de um hash SHA (não pode aparecer)

```bash
go test ./engine/... -run TestMotoresJuntos
```

### Critério de saída

- [ ] Um scan devolve achados dos dois motores no mesmo formato
- [ ] O CPF inválido não aparece
- [ ] O CPF dentro do hash não aparece
- [ ] Trocar a implementação do motor de segredos não exige mudar nada fora de `engine/secrets/`

**Risco:** a v2 do betterleaks ainda está em branch. A interface `Engine` é o seguro; se a API mudar, muda um arquivo.

---

## M3 — 🎯 MVP: superfície de IA

**Objetivo.** Impedir que segredo e dado pessoal cheguem ao contexto do modelo — e mostrar o que já chegou.

**É aqui que o projeto passa a existir para o mundo.** Duas entregas, dois GIFs.

### Contexto do problema

Documentado nas issues do próprio Claude Code:
- [#44868](https://github.com/anthropics/claude-code/issues/44868) — expõe segredo de `.env` via `grep` e `Read`, mesmo com proibição no CLAUDE.md
- [#50014](https://github.com/anthropics/claude-code/issues/50014) — pedido de scrubbing dos logs de sessão
- [#95680](https://github.com/anthropics/claude-code/issues/95680) — segredo que entra por tool call se espalha por todos os stores em disco, sem forma de limpar

Nenhum provedor faz redação antes do contexto. Os transcripts ficam em `~/.claude/projects/*.jsonl`, texto puro, sem criptografia, sem rotação.

### O que implementar

**3.1 — `vedei stream`** (prevenção)

```bash
cat .env | vedei stream          # stdout tarjado
echo $?                           # 0 = limpo, 3 = achou, 1 = erro
```

- lê stdin, escreve stdout tarjado
- preserva o formato: `AWS_KEY=AKIA****************` e `CPF: ***.***.**9-09`
- **fail-open**: erro interno deixa o texto passar intacto (quebrar a sessão do usuário é pior que não tarjar)

**3.2 — Hook de agente**

`hooks/claude-code/` e `hooks/codex/`, prontos para copiar. `PostToolUse`: a saída da ferramenta passa pelo vedei antes de voltar ao modelo.

**3.3 — Modo daemon** ✅

Socket Unix, config pré-compilada carregada uma vez. É o que viabiliza o orçamento de 10 ms.

```bash
vedei daemon                    # primeiro plano; launchd/systemd em hooks/
vedei daemon status             # 0 responde, 1 não responde
vedei daemon --idle-timeout 8h  # sai sozinho quando não é usado
```

O daemon sozinho não bastou. Medindo, detecção era 0,26 ms e o resto era setup: ~14 ms compilando as 417 regras e ~7 ms carregando um binário de 26 MB. O daemon tira os 14 ms e deixa 13,3 ms — ainda acima do orçamento, porque o que sobra é o próprio processo nascer.

Daí o segundo binário, **`vedei-hook`**: 5 MB, não importa o betterleaks, não detecta nada. Só fala com o socket. Com o daemon de pé, **8,4 ms p95**.

Nada exige o daemon (ADR-005): sem ele, `vedei-hook` executa o binário completo. Isso custa 36,3 ms — pior que chamar `vedei hook` direto, porque são dois processos. Quem não vai rodar daemon deve configurar `vedei hook`, e a doc do hook diz isso primeiro.

**3.4 — `vedei transcript scan`** (o que já vazou)

```bash
vedei transcript scan                      # detecta ~/.claude, ~/.codex
vedei transcript scan --path ~/.claude/projects/
```

Relatório: quais transcripts contêm o quê, desde quando, quantas ocorrências. **Somente leitura nesta etapa** — o `scrub`, que reescreve, fica no M4, onde existe backup e dry-run.

Vale como camada de cibersegurança: quem compromete a máquina, ou rouba o notebook, lê esses arquivos. O `.env` tem gitignore e permissão; o transcript não tem nada, e agrega segredos de várias fontes num arquivo só que nenhuma ferramenta vigia.

### Passo a passo

1. `redact/` — tarja preservando formato
2. `vedei stream` sobre os dois motores
3. Medir latência. Se passar de 10 ms, implementar o daemon antes de seguir.
4. Hook do Claude Code + instalador
5. Hook do Codex
6. `transcript/` — parser de JSONL dos dois formatos
7. `vedei transcript scan` + relatório
8. Gravar os dois GIFs

### Como testar

**Latência (é o teste que define o milestone):**
```bash
make bench-hook    # p50, p95, p99 sobre saidas tipicas de ferramenta
```

**Fail-open:**
```go
func TestStream_FailOpen(t *testing.T) {
    // motor que sempre entra em panico
    out := stream(entradaQualquer, motorQuebrado{})
    require.Equal(t, entradaQualquer, out)  // texto intacto
}
```

**Manual, e é o que vale:** numa sessão real do Claude Code, com o hook instalado, rodar `cat` num arquivo contendo CPF válido e chave AWS. Verificar que o modelo recebeu tarjado.

**Transcript:** gerar um `.jsonl` sintético com segredo conhecido, rodar o scan, conferir que achou e que **não imprimiu o valor** no relatório.

### Critério de saída

- [x] p95 do hook medido e documentado — **8,4 ms** com `vedei-hook` + daemon,
      dentro do orçamento de 10 ms. A primeira medição, com um processo por
      chamada, deu 28,9 ms; o orçamento era um chute feito antes de existir o
      que medir e acabou alcançável, mas só depois de atacar setup em vez de
      detecção. Tabela completa em `hooks/README.md`.
- [x] Sessão real: `cat` de arquivo com segredo chega tarjado ao modelo.
      **Aqui estava o bug mais grave do repositório**: o motor de segredos
      preenchia linha e coluna, nunca `ByteStart`/`ByteEnd`, e
      `stream.Processor` tarja por offset. Toda credencial era anunciada como
      tarjada no stderr e entregue ao modelo intacta. Coberto agora em três
      camadas: `engine/secrets` (offsets existem e apontam para o valor),
      `engine` (o texto que sai do processor não contém o segredo) e
      `cmd/vedei-hook` (o evento que volta ao agente não contém o segredo).
- [x] Motor em pânico deixa o texto passar intacto — `TestProcess_FailsOpenOnPanic`
- [x] `transcript scan` acha segredo conhecido e não vaza o valor no relatório
- [ ] Dois GIFs no README — pendente, precisa de gravação de tela

**Riscos**
- **Latência** é o que mata. Hook que atrasa 200 ms por tool call ninguém usa.
- **Falso positivo aqui é pior que em CI**: tarjar algo que o agente precisava quebra a tarefa. Começar conservador — só `ValidityStructural` e `ConfidenceHigh`.

**O que rodar de verdade encontrou, e teste nenhum tinha pego**

1. **Segredo detectado e não tarjado** (acima). O stderr dizia `redacted`, o texto saía com a chave. Um ano de testes de unidade em `engine/secrets` não pegaria: cada peça estava certa, o contrato entre elas não.
2. **`card-pan` dentro de um UUID.** `11111111-2222-3333-4444-555555555555` virava cartão `4444-555555555555`, confiança alta — 16 dígitos que passam Luhn por coincidência. O padrão aceitava cada separador de forma independente. Agora exige agrupamento consistente: sem separador, ou grupos de 4 com o mesmo separador.
3. **`chmod` no diretório pai do socket** falhava em `/tmp` (`operation not permitted`). Restringir o diretório só é vedei quando vedei o criou.
4. **O daemon não desligava** com um cliente conectado e ocioso: fechar o listener não fecha conexões aceitas, então `SIGTERM` esperava para sempre.
5. **Caminho de socket > 104 bytes** falha com `EINVAL` puro no macOS, que não diz nada. Agora é checado com a correção na mensagem.

**Lacuna conhecida, não corrigida:** o betterleaks não tem regra para AWS access key ID (`AKIA…`) — nem a canônica de exemplo, nem uma aleatória. Stripe, GitHub PAT e Slack são detectados. É uma decisão defensável do upstream (um access key ID é identificador, não credencial), mas para o propósito aqui é um vazamento que passa. Fica para o M5, junto com o corpus.

---

## M4 — CLI, CI/CD, SARIF, scrub

**Objetivo.** Onde a adoção acontece.

### O que implementar

1. `vedei scan <path>`, `vedei git <repo>`, `vedei diff`
2. Relatório **JSON, JSONL e SARIF** — SARIF é estratégico: a v2 do betterleaks vai removê-lo, e é o que o GitHub Code Scanning consome
3. GitHub Action publicada no Marketplace
4. Hooks de `pre-commit` e `pre-receive`
5. Comentário inline em PR
6. `.vedeiignore` com fingerprint estável
7. **Códigos de saída distintos**: `0` limpo, `3` achou, `1` erro operacional (é a issue #347 do betterleaks; não repetir)
8. **`vedei transcript scrub`** — reescreve o transcript tarjado, com `--dry-run` obrigatório na primeira execução, backup automático e confirmação

### Passo a passo

1. CLI com cobra; reusar o núcleo, sem lógica nova
2. Caminhador de diretório com respeito a `.gitignore`
3. Relatórios, SARIF por último (é o mais chato)
4. Códigos de saída e `.vedeiignore`
5. GitHub Action
6. `transcript scrub` com backup e dry-run

### Como testar

**SARIF:** validar contra o schema oficial e subir de verdade na aba Security do próprio repositório.

**Código de saída:**
```bash
vedei scan limpo/;           [ $? -eq 0 ]
vedei scan com-segredo/;     [ $? -eq 3 ]
vedei scan /sem/permissao/;  [ $? -eq 1 ]
```

**Scrub:** copiar um transcript, rodar scrub, verificar que (a) o segredo sumiu, (b) o JSONL continua válido, (c) o backup existe e é idêntico ao original.

### Critério de saída

- [x] A Action roda no próprio repositório e publica na aba Security —
      `.github/workflows/vedei.yml`, com `mode: diff` em PR e `mode: history`
      semanal. Ela usa o binário construído do checkout, não o publicado:
      escanear a si mesmo com o release do mês passado prova menos do que parece.
- [x] Os três códigos de saída conferem, e `1` tem precedência sobre `3` —
      "achamos duas coisas" engana quando a varredura não terminou.
- [x] `scrub` não corrompe JSONL; backup verificado por hash, não por tamanho
- [x] Varredura de diretório > 50 MB/s — medido em quatro formas, porque
      respondem a perguntas diferentes (9,8 MB em 300 arquivos, Apple M4):
      **218 MB/s** quente e em processo com os dois motores, **246 MB/s** só
      dados BR, **99 MB/s** numa execução da CLI pelo tempo que ela mesma
      reporta, e **72 MB/s** de relógio de parede (~137 ms). A diferença entre a
      primeira e a terceira é custo único que o benchmark amortiza e o usuário
      de linha de comando paga sempre: compilar 417 regras e carregar 26 MB de
      binário. Citar só os 218 seria citar o número que ninguém experimenta.
      Benchmark em `scan/bench_test.go`, reportando sem assertar.
- [x] `.vedeiignore` no próprio repo: 71 achados silenciados, 21 fingerprints,
      cada um com o motivo escrito. Nada silenciado por caminho, de propósito.

**Comentário inline em PR** (item 5) **não foi implementado, e não deve ser.**
O upload de SARIF para o Code Scanning já anota o diff do PR, com deduplicação,
estado de alerta e histórico — um bot de comentário próprio seria uma segunda
fonte de verdade pior que a primeira. Fica registrado como decisão, não como
pendência.

**Risco:** escopo. Resistir a adicionar fontes novas (S3, GitLab, Hugging Face) — o betterleaks já faz e você herda.

**O que rodar no próprio repositório encontrou**

1. **Timestamp virando número de cartão.** `20240915155400` — o timestamp dentro
   de uma pseudo-versão do Go, no `go.mod` — passou por Luhn e saiu como
   `card-pan` com confiança alta. Luhn passa em ~1 de cada 10 sequências
   aleatórias, e `YYYYMMDDHHMMSS` está em pseudo-versão de módulo, log, nome de
   arquivo e nome de migration. Agora uma sequência **sem separador** também
   precisa começar numa faixa de emissor conhecida; nenhuma bandeira emite número
   começando em 19, 20 ou 21. Quem escreve em grupos de quatro está isento — o
   formato é a evidência, ninguém escreve timestamp como `2024 0915 1554 00`.
2. **`.vedeiignore` só valia para fingerprint**, não para o caminhamento, então
   uma regra de caminho lá não pulava nada.
3. **Caminhos absolutos no relatório.** O SARIF do GitHub casa o caminho contra a
   árvore do repositório, então um caminho absoluto põe o alerta em arquivo
   nenhum. O scanner reporta relativo à raiz por isso, não por estética.

---

## M5 — Corpus multilíngue + calibração pt-BR

**Objetivo.** Transformar falso positivo de opinião em métrica, e corrigir um viés medido.

### A hipótese original — e o que a medição mostrou

**A hipótese era de precision.** O filtro de token efficiency do betterleaks descarta um candidato como prosa quando ele contém uma palavra de um dicionário de 33.775 palavras **em inglês**; senão compara a razão caracteres/token com 2,5. Medida isolada, essa razão dava `senhapadrao` = 2,20 e `defaultpassword` = 7,50, e daí se concluiu que placeholder em português seria reportado como segredo.

**Medido de ponta a ponta (betterleaks v1.8.1), não é.** Só a regra `generic-api-key` usa esse filtro, e a cadeia completa rejeita placeholders em prosa nos três idiomas igualmente — 0 de 30 em inglês, português e espanhol. A conclusão vinha de olhar a razão fora da cadeia de filtros.

**O viés real era de recall, e era maior.** As regras reconhecem nomes de chave em inglês. Com o mesmo segredo real sob nomes equivalentes:

| idioma da chave | segredos reais achados |
|---|---:|
| inglês | 100% |
| espanhol | 57% |
| português | **29%** |

`senha`, `segredo` e `senha_banco` nunca eram reconhecidos. As chaves em português que funcionavam (`chave_api`, `token_acesso`) funcionavam só por conter `api` e `token`.

### O que foi implementado

1. **`corpus/`** com formato rotulado (`expect` / `reject`), gate estrito e métrica **por tipo** — ✅
2. **Passada de localização** em `engine/secrets/localize.go`: nomes de chave em português e espanhol que recebem atribuição são traduzidos (`senha`→`password`, `segredo`→`secret`, `chave`→`key`…) e o texto é escaneado de novo pelas **mesmas regras**. Valores nunca são reescritos, então o segredo é localizado no texto original. Os filtros do upstream — que também têm inglês embutido — se aplicam inteiros, o que dá paridade em vez de uma regra paralela com precision própria — ✅
3. **Reordenação head-final**: português e espanhol nomeiam `senha_banco`; inglês nomeia `db_password`, e a regra do upstream exige fronteira de palavra logo depois de `password`, então `password_db` falha até em inglês. A tradução move `password` para o fim — ✅

Resultado, mesmos valores sob chaves equivalentes: recall **100%** em português e espanhol (inglês 88%, por causa do `password_db` que o próprio upstream perde). Falsos positivos com placeholders são iguais por chave nos três idiomas.

**Não implementado, e por quê:** o dicionário pt-BR para o filtro de token efficiency (itens 1–2 do plano original). A medição mostrou que ele não corrigiria nada.

### Achado lateral — fora do escopo do M5

A `generic-password` do upstream reporta placeholders instrucionais com confiança baixa **em qualquer idioma**: `"your-password-here"`, `"replace_me"`, `"changeme"` e seus equivalentes `"sua-senha-aqui"`, `"troque_isto"` — 5 de 10 em cada idioma. Referências (`${VAR}`, `os.getenv`, `<marcador>`) são suprimidas corretamente nos três. É fraqueza de precision do upstream, neutra de idioma; candidata a issue no betterleaks ou a um filtro do vedei num marco próprio.

### Como testar

`make corpus` (também roda em `go test ./...`, portanto no CI). A tabela por tipo aparece no log.

### Critério de saída

- [ ] `corpus/` com ≥ 500 casos rotulados, em 3 idiomas — **119 hoje, nos 3 idiomas**
- [x] Corpus no CI, falhando em regressão — `corpus_test.go` roda dentro de `go test ./...`
- [x] Número publicado no README — recall por idioma e precision/recall por tipo
- [ ] Issue aberta no betterleaks com a medição (recall por idioma + `password_db`)

**Risco:** nenhum técnico. É curadoria — chato, e é por isso que ninguém fez.

---

## M6 — SDK de runtime

**Objetivo.** Prevenir em vez de detectar depois.

### O que implementar

1. Go: `slog.Handler` que tarja antes de escrever
2. Go: middleware HTTP que inspeciona corpo de resposta antes de sair, com limite de tamanho e desligável por rota
3. Node/TypeScript e Python — via binário auxiliar ou CGO

### Como testar

```go
func BenchmarkHandler_SemAchado(b *testing.B) { ... }  // alvo: < 1 µs
```

Teste de integração: app de exemplo, `log.Info("cpf", cpf)` sai tarjado.

### Critério de saída

- [ ] Overhead < 1 µs por chamada quando não há achado
- [ ] App de exemplo logando tarjado
- [ ] Middleware não altera resposta sem achado (comparação byte a byte)

**Risco:** escopo de linguagem. Go primeiro e bem; Node e Python só depois de decidir se valem a manutenção.

---

## M7 — Camada de IA

**Objetivo.** Usar modelo onde ele genuinamente ajuda, e em nenhum outro lugar.

**Depois do M5, nunca antes** — sem corpus rotulado não há como provar que a triagem melhora nada.

### O que implementar

1. **Triagem assistida** — classifica em `real | teste | exemplo de doc | placeholder`, recebendo só contexto **redigido**: caminho, nome da variável, linha mascarada, forma do valor, entropia, vizinhança. Vira atributo, **nunca filtro** (ADR-004).
2. **Geração assistida de regra** — tempo de desenvolvimento; recebe documentação de API e rascunha regra + casos de teste. Validação automática obrigatória antes de mesclar.
3. **Servidor MCP** — `scan_text`, `validate_structure`, `explain_finding`. Confirmação explícita em qualquer operação de rede.
4. **Narrativa de severidade** em português.

### Como testar

**O teste que importa (ADR-003):**
```go
func TestIA_NuncaVazaValor(t *testing.T) {
    // intercepta TODO payload de saida da camada ai/
    // falha se qualquer um contiver o valor detectado
}
```
Roda no CI. É bloqueante.

**Eficácia:** rodar a triagem contra o corpus do M5 e medir o ganho de precisão.

### Critério de saída

- [ ] Teste de não vazamento no CI, bloqueante
- [ ] Ganho de precisão publicado no README — **inclusive se for zero**
- [ ] Modelo local (Ollama) funciona, sem depender de API externa

**Riscos**
- Vazamento pelo próprio recurso é o pior incidente possível para este projeto.
- Dependência de fornecedor: suportar modelo local desde o início.

---

## M8 — Coletor de observabilidade

**Objetivo.** Detectar PAN e CPF onde eles de fato vazam em fintech.

### O que implementar

1. Processador de OpenTelemetry Collector
2. Integrações: Loki, Datadog, Sentry
3. Modo tarja em tempo real e modo alerta
4. Amostragem configurável

### Como testar

Ambiente de demonstração com collector real; log com PAN válido chega tarjado no backend.

### Critério de saída

- [ ] PAN tarjado antes de chegar ao backend, em ambiente real
- [ ] Amostragem configurável e documentada
- [ ] Overhead medido e publicado

**Risco:** é o mais difícil de operar e o que mais exige confiança. Por isso vem depois de tudo.

---

## M9 — Validação de segredo + allowlist de destino

**Objetivo.** Ligar validação ao vivo sem herdar o buraco do betterleaks.

### Contexto

No betterleaks, `http.get/post` na expressão de validação aceita **URL arbitrária**: sem allowlist de host, sem bloqueio de IP privado nem de `169.254.169.254`. E a config é carregada de `(alvo)/.betterleaks.toml` — do repositório escaneado. Hoje é contido porque validação é opt-in; **na v2 ela passa a ser padrão**.

### O que implementar

1. Validação de segredo habilitada, delegada ao betterleaks
2. `--validation-allow-hosts` — allowlist derivada por padrão dos hosts que aparecem no config padrão; host fora dela exige flag explícita
3. Bloqueio de IP privado, loopback, link-local e metadados, com **DNS pinado antes de conectar**
4. Aviso quando a config vier do diretório escaneado e contiver `validate`
5. Contribuir o controle de volta para o betterleaks

### Como testar

```go
func TestAllowHosts_RecusaHostNaoPermitido(t *testing.T)
func TestAllowHosts_RecusaIPPrivado(t *testing.T)
func TestAllowHosts_RecusaDNSRebinding(t *testing.T)  // DNS resolve para 127.0.0.1
```

### Critério de saída

- [ ] Config maliciosa apontando para host não permitido é recusada, com teste
- [ ] DNS rebinding é bloqueado
- [ ] PR ou issue aberta no betterleaks

---

## M10 — v1.0

**Objetivo.** Deixar de ser projeto pessoal.

### O que implementar

1. Documentação completa, pt-BR e inglês
2. Garantia de estabilidade de API e política de versionamento
3. Governança: como um detector novo é aceito, quem revisa
4. Comparação honesta: quando usar vedei, quando usar betterleaks, quando usar os dois
5. Auditoria do próprio projeto (rodar vedei e betterleaks em si mesmo)

### Critério de saída

- [ ] Cobertura geral ≥ 80%
- [ ] O projeto passa no próprio scanner
- [ ] Alguém que você não conhece abriu uma issue ou um PR
