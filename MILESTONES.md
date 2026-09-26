# nadzor — Milestones

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

1. `go.mod` — módulo `github.com/mkmuniz/nadzor`, Go 1.25
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
- [ ] `nadzor` como biblioteca: `br.Scan([]byte("cpf 123.456.789-09"))` devolve 1 achado válido

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

**3.1 — `nadzor stream`** (prevenção)

```bash
cat .env | nadzor stream          # stdout tarjado
echo $?                           # 0 = limpo, 3 = achou, 1 = erro
```

- lê stdin, escreve stdout tarjado
- preserva o formato: `AWS_KEY=AKIA****************` e `CPF: ***.***.**9-09`
- **fail-open**: erro interno deixa o texto passar intacto (quebrar a sessão do usuário é pior que não tarjar)

**3.2 — Hook de agente**

`hooks/claude-code/` e `hooks/codex/`, prontos para copiar. `PostToolUse`: a saída da ferramenta passa pelo nadzor antes de voltar ao modelo.

**3.3 — Modo daemon**

Socket Unix, config pré-compilada carregada uma vez. É o que viabiliza o orçamento de 10 ms.

**3.4 — `nadzor transcript scan`** (o que já vazou)

```bash
nadzor transcript scan                      # detecta ~/.claude, ~/.codex
nadzor transcript scan --path ~/.claude/projects/
```

Relatório: quais transcripts contêm o quê, desde quando, quantas ocorrências. **Somente leitura nesta etapa** — o `scrub`, que reescreve, fica no M4, onde existe backup e dry-run.

Vale como camada de cibersegurança: quem compromete a máquina, ou rouba o notebook, lê esses arquivos. O `.env` tem gitignore e permissão; o transcript não tem nada, e agrega segredos de várias fontes num arquivo só que nenhuma ferramenta vigia.

### Passo a passo

1. `redact/` — tarja preservando formato
2. `nadzor stream` sobre os dois motores
3. Medir latência. Se passar de 10 ms, implementar o daemon antes de seguir.
4. Hook do Claude Code + instalador
5. Hook do Codex
6. `transcript/` — parser de JSONL dos dois formatos
7. `nadzor transcript scan` + relatório
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

- [ ] p95 do hook < 10 ms em saída típica
- [ ] Sessão real: `cat` de arquivo com segredo chega tarjado ao modelo
- [ ] Motor em pânico deixa o texto passar intacto
- [ ] `transcript scan` acha segredo conhecido e não vaza o valor no relatório
- [ ] Dois GIFs no README

**Riscos**
- **Latência** é o que mata. Hook que atrasa 200 ms por tool call ninguém usa.
- **Falso positivo aqui é pior que em CI**: tarjar algo que o agente precisava quebra a tarefa. Começar conservador — só `ValidityStructural` e `ConfidenceHigh`.

---

## M4 — CLI, CI/CD, SARIF, scrub

**Objetivo.** Onde a adoção acontece.

### O que implementar

1. `nadzor scan <path>`, `nadzor git <repo>`, `nadzor diff`
2. Relatório **JSON, JSONL e SARIF** — SARIF é estratégico: a v2 do betterleaks vai removê-lo, e é o que o GitHub Code Scanning consome
3. GitHub Action publicada no Marketplace
4. Hooks de `pre-commit` e `pre-receive`
5. Comentário inline em PR
6. `.nadzorignore` com fingerprint estável
7. **Códigos de saída distintos**: `0` limpo, `3` achou, `1` erro operacional (é a issue #347 do betterleaks; não repetir)
8. **`nadzor transcript scrub`** — reescreve o transcript tarjado, com `--dry-run` obrigatório na primeira execução, backup automático e confirmação

### Passo a passo

1. CLI com cobra; reusar o núcleo, sem lógica nova
2. Caminhador de diretório com respeito a `.gitignore`
3. Relatórios, SARIF por último (é o mais chato)
4. Códigos de saída e `.nadzorignore`
5. GitHub Action
6. `transcript scrub` com backup e dry-run

### Como testar

**SARIF:** validar contra o schema oficial e subir de verdade na aba Security do próprio repositório.

**Código de saída:**
```bash
nadzor scan limpo/;           [ $? -eq 0 ]
nadzor scan com-segredo/;     [ $? -eq 3 ]
nadzor scan /sem/permissao/;  [ $? -eq 1 ]
```

**Scrub:** copiar um transcript, rodar scrub, verificar que (a) o segredo sumiu, (b) o JSONL continua válido, (c) o backup existe e é idêntico ao original.

### Critério de saída

- [ ] A Action roda no próprio repositório e publica na aba Security
- [ ] Os três códigos de saída conferem
- [ ] `scrub` não corrompe JSONL; backup verificado byte a byte
- [ ] Varredura de diretório > 50 MB/s

**Risco:** escopo. Resistir a adicionar fontes novas (S3, GitLab, Hugging Face) — o betterleaks já faz e você herda.

---

## M5 — Corpus multilíngue + calibração pt-BR

**Objetivo.** Transformar falso positivo de opinião em métrica, e corrigir um viés medido.

### O problema, com número

O filtro de token efficiency do betterleaks usa dicionário de 33.775 palavras **em inglês** e limiar fixo de 2,5 caracteres por token. Medido com o tokenizador que ele mesmo embute:

| String | Razão | Resultado |
|---|---:|---|
| `defaultpassword` | 7,50 | descartado, correto |
| `senhapadrao` | **2,20** | **reportado como segredo** |
| `cobrancaboleto` | **2,33** | **reportado como segredo** |
| segredo real | 1,0–1,6 | reportado, correto |

Em inglês a separação entre prosa e segredo é confortável. Em português quase some. Ninguém mediu isso.

### O que implementar

1. Dicionário pt-BR embutido, mesmo mecanismo `go:embed` + gzip
2. `--locale pt-BR`, com detecção automática do idioma predominante do repositório
3. **`corpus/`** — strings reais de código em pt, en, es, com rótulo esperado
4. `make fp-report` — imprime precisão e recall do conjunto; **falha o CI se regredir**
5. Publicar a medição como issue no betterleaks

### Como testar

O próprio `make fp-report` é o teste. Roda no CI, com limiar mínimo travado.

### Critério de saída

- [ ] `corpus/` com ≥ 500 casos rotulados, em 3 idiomas
- [ ] `make fp-report` no CI, falhando em regressão
- [ ] Número de precisão publicado no README
- [ ] Issue aberta no betterleaks com a medição

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
4. Comparação honesta: quando usar nadzor, quando usar betterleaks, quando usar os dois
5. Auditoria do próprio projeto (rodar nadzor e betterleaks em si mesmo)

### Critério de saída

- [ ] Cobertura geral ≥ 80%
- [ ] O projeto passa no próprio scanner
- [ ] Alguém que você não conhece abriu uma issue ou um PR
