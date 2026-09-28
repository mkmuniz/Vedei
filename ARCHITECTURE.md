# nadzor — Arquitetura

Documento de referência técnica. Define os componentes, o fluxo de dados, os contratos entre módulos e os orçamentos de desempenho. O plano de execução está em [`MILESTONES.md`](MILESTONES.md).

---

## 1. Visão geral

nadzor tem **um núcleo** e **quatro adaptadores**. O núcleo não sabe de onde o texto veio nem para onde o resultado vai.

```
   ENTRADA (adaptadores)                NÚCLEO                     SAÍDA
┌──────────────────────┐      ┌──────────────────────┐    ┌──────────────────┐
│ hook de agente (M3)  │      │                      │    │ texto tarjado    │
│ transcript  (M3)     │      │   Scanner            │    │ JSON / JSONL     │
│ CLI / CI    (M4)     │─────▶│   ├─ engine/br       │───▶│ SARIF            │
│ SDK runtime (M6)     │      │   └─ engine/secrets  │    │ código de saída  │
│ coletor otel(M8)     │      │                      │    │                  │
└──────────────────────┘      └──────────────────────┘    └──────────────────┘
```

Regra que mantém isso honesto: **um adaptador novo nunca adiciona lógica de detecção.** Se um adaptador precisa detectar algo novo, isso vira detector no núcleo.

---

## 2. Os dois motores

A decisão central do projeto. Dois tipos de dado, duas formas de validar, dois perfis de risco.

| | `engine/br` | `engine/secrets` |
|---|---|---|
| Detecta | CPF, CNPJ, CIN, CNH, PIS, título, CNS, PAN, chave Pix, E2EID | 463 regras de credencial |
| Implementação | código próprio | [betterleaks](https://github.com/betterleaks/betterleaks) (MIT) como biblioteca |
| Validação | dígito verificador, Luhn, ISPB | requisição HTTP ao provedor |
| Rede | **nunca** | opcional, desligada por padrão |
| Latência | microssegundos | 50–500 ms |
| Determinístico | sim | não (depende do provedor) |

**Por que importa:** o motor `br` pode rodar no caminho quente (hook de agente, middleware de log) porque é offline e previsível. O motor `secrets` com validação ligada nunca pode — fica em CI e em análise assíncrona.

---

## 3. A interface `Engine`

Todo motor implementa o mesmo contrato. É o que permite trocar o betterleaks v1 por v2 sem tocar em nada mais.

```go
package detect

type Engine interface {
    // Scan e' puro: nao escreve em disco, nao faz IO alem do que o
    // motor declara em Capabilities(). Deve ser seguro para chamada
    // concorrente.
    Scan(ctx context.Context, content []byte, meta Metadata) ([]Finding, error)

    // Capabilities declara o que este motor faz, para que o chamador
    // decida se pode usa-lo no caminho quente.
    Capabilities() Capabilities
}

type Capabilities struct {
    RequiresNetwork bool          // true = proibido em hook e middleware
    TypicalLatency  time.Duration
    Deterministic   bool
}
```

`Metadata` carrega o contexto da origem sem acoplar o núcleo a ela:

```go
type Metadata struct {
    Path     string            // caminho do arquivo, quando existe
    Source   string            // "fs" | "git" | "stdin" | "transcript" | "otel" | "runtime"
    Extra    map[string]string // git.sha, git.author, otel.service, ...
}
```

---

## 4. O tipo `Finding`

Estrutura única para os dois motores. **O valor nunca é serializado em claro por padrão.**

```go
type Finding struct {
    Type       string      // "cpf" | "cnpj" | "pan" | "pix-key" | "aws-access-key" | ...
    Engine     string      // "br" | "secrets"

    Value      string      // SEMPRE redigido na saida; o valor bruto vive
                           // apenas em memoria e so' e' exposto por opt-in explicito
    Raw        string      `json:"-"` // nunca serializado

    Valid      Validity    // ver abaixo
    Confidence Confidence  // low | medium | high
    Severity   Severity    // preenchido no M7

    Location   Location    // path, linha, coluna, offset
    Reason     string      // "check digit ok" | "ISPB 60701190 = Itau" | "luhn failed"
    Fingerprint string     // SHA-256 estavel: nao muda se a linha se mover
}

type Validity int
const (
    ValidityUnknown    Validity = iota // nao ha' como validar (ex.: RG)
    ValidityStructural                 // digito verificador fecha
    ValidityInvalid                    // digito verificador nao fecha -> descartado
    ValidityLive                       // credencial respondeu que esta' ativa
    ValidityRevoked
)
```

`ValidityInvalid` **não vira achado**. Se o dígito não fecha, não é CPF. É a origem da promessa de zero falso positivo estrutural.

---

## 5. Fluxo de um dado

```
 texto bruto
     │
 [1] prefilter      descarta o fragmento inteiro por caminho/origem
     │              (ex.: node_modules, testdata, binario)
     │
 [2] extract        regex por detector, tolerante a mascara
     │              123.456.789-09 / 12345678909 / 123.456.78909
     │
 [3] validate       digito verificador | Luhn | ISPB | estrutura
     │              -> invalido morre aqui, nao vira achado
     │
 [4] classify       confidence: alta se validou + contexto bate
     │                          baixa se validou mas contexto ausente
     │
 [5] dedupe         mesmo valor em varios lugares = um achado, N locations
     │
 [6] output         redact (tarja) | report (JSON/SARIF) | exit code
```

Etapa 3 é o que separa nadzor de um scanner de regex. Um `grep` de CPF acha `000.000.000-00`; nadzor não, porque o dígito não fecha.

**Divergência conhecida na etapa 2.** "Tolerante a máscara" não é uniforme entre detectores. CNS, título e PAN aceitam espaço como separador; CPF, CNPJ e PIS aceitam só `.`, `-` e `/`. Então `529 982 247 25` **não** é detectado como CPF hoje. Isso foi descoberto escrevendo um teste que assumia o contrário, e é uma decisão de calibração, não um esquecimento: aceitar espaço no CPF casa com qualquer coluna de tabela de três dígitos, e medir esse custo é justamente o que o corpus do M5 existe para fazer. Até lá o comportamento está documentado aqui em vez de prometido no código.

---

## 6. Orçamentos de desempenho

Cada superfície tem um limite diferente. Ultrapassar o limite é bug, não lentidão.

| Superfície | Orçamento | Por quê |
|---|---|---|
| Hook de agente | **< 10 ms** p95 por chamada de ferramenta — medido: **8,4 ms** com daemon | roda a cada tool call; 200 ms torna o agente inutilizável |
| Middleware de log | **< 1 µs** quando não há achado | roda a cada linha de log de produção |
| CLI / CI | throughput, não latência | alvo: > 50 MB/s em varredura de diretório |
| Coletor otel | amostrável | inspecionar 100% do log de produção tem custo; deve ser configurável |

Consequência de projeto: config é **pré-compilada uma vez** e reaproveitada. Recarregar e recompilar regra por invocação custa ~14 ms — é o bug conhecido do betterleaks (issue #343) e não deve ser repetido.

O orçamento de 10 ms era um chute feito antes de existir o que medir, e a primeira medição do hook pronto deu 28,9 ms. A decomposição mostrou que detecção era 1% da conta:

| custo | tempo |
|---|---:|
| detecção em si | 0,26 ms |
| compilar as 417 regras de segredo | ~14 ms |
| carregar um binário de 26 MB | ~7 ms |
| spawn do processo + init do runtime Go | ~5 ms |

Duas mudanças fecharam a diferença, e as duas atacam setup, não detecção (ADR-006):

1. **`nadzor daemon`** mantém as regras compiladas atrás de um socket Unix. Tira os 14 ms.
2. **`nadzor-hook`**, cliente de 5 MB que não importa o betterleaks. Tira ~6 dos 7 ms de carga.

Resultado medido, p95 sobre 110 chamadas: **8,4 ms**. Sem daemon, `nadzor hook` continua funcionando a 28,9 ms — nada exige o daemon (ADR-005).

---

## 7. Decisões de arquitetura (ADRs)

**ADR-001 — Reusar o betterleaks em vez de reimplementar.**
463 regras de segredo são anos-pessoa. O betterleaks é MIT e a v2 é explicitamente desenhada como biblioteca (módulo `/v2`, split Scanner/Analyzer). Consequência: nadzor herda o corpus e gasta 100% do esforço no que não existe. Risco: a v2 ainda está em branch — mitigado pela interface `Engine`, que isola a troca.

**ADR-002 — Dado pessoal é validado estruturalmente, nunca contra base oficial.**
Consultar Receita Federal a partir de um CPF achado em log criaria um problema de LGPD maior que o detectado. nadzor afirma "é um CPF estruturalmente válido", nunca "é o CPF do fulano". Consequência: o motor `br` é 100% offline, o que elimina rate limit, SSRF e dependência de terceiro.

**ADR-003 — O valor detectado nunca chega a um modelo de linguagem.**
Nem em triagem, nem em explicação, nem em telemetria. Uma ferramenta que detecta credencial e a manda para uma API de LLM criou um vazamento novo. Consequência: a camada de IA (M7) trabalha só com contexto redigido, e há teste de CI que falha se qualquer payload de saída contiver um valor detectado.

**ADR-004 — Saída de modelo é sinal, nunca filtro.**
Classificação não determinística pode reordenar fila de triagem. Não pode descartar achado silenciosamente.

**ADR-005 — Fail-open na tarja, fail-closed no relatório.**
Erro no hook deixa o texto passar (quebrar a sessão do usuário é pior). Erro na varredura de CI falha a varredura (reportar "limpo" quando quebrou é pior).

**ADR-006 — Um daemon guarda as regras compiladas, e o cliente do hook é pequeno.**
Detecção custa 0,26 ms; setup custava 28,6 ms e era refeito a cada tool call. O daemon compila uma vez e responde num socket Unix `0600`, domínio Unix apenas — o que atravessa esse socket é texto que acabou de ser julgado sensível, então não existe modo TCP. `nadzor-hook` tem 5 MB porque não importa o betterleaks. Nada exige o daemon: todo chamador cai para varredura em processo.

---

## 8. Estrutura de pastas

```
nadzor/
├── cmd/nadzor/            # CLI (cobra) + o daemon
├── cmd/nadzor-hook/       # cliente magro do hook          (M3)
│
├── detect/
│   ├── types.go           # Finding, Validity, Confidence, Location
│   ├── engine.go          # interface Engine + Capabilities
│   └── br/                # ★ NUCLEO — validadores puros, zero dependencia
│       ├── cpf.go         cpf_test.go
│       ├── cnpj.go        cnpj_test.go      # numerico + alfanumerico
│       ├── cnh.go         pis.go   titulo.go   cns.go
│       ├── luhn.go        # PAN
│       ├── pix.go         # chave Pix por tipo
│       ├── e2eid.go       # + consulta ISPB
│       ├── extract.go     # regex tolerante a mascara
│       └── assets/ispb.json.gz
│
├── engine/
│   ├── br/                # implementa Engine sobre detect/br
│   └── secrets/           # implementa Engine embrulhando betterleaks
│
├── redact/                # tarja preservando formato
├── report/                # JSON, JSONL, SARIF
├── fingerprint/           # SHA-256 estavel do achado
│
├── stream/                # stdin -> stdout            (M3)
├── daemon/                # servidor e cliente do socket Unix (M3)
├── internal/hookevent/    # parse/rewrite do evento de hook (M3)
├── transcript/            # leitor de *.jsonl de agente (M3/M4)
├── hooks/                 # Claude Code, Codex, launchd, systemd (M3)
├── sdk/{go,node,python}/  #                             (M6)
├── otel/                  #                             (M8)
├── ai/                    # triagem, geracao de regra, MCP (M7)
│
├── corpus/                # ★ corpus multilingue de falso positivo (M5)
└── docs/{pt-br,en}/
```

Os dois `★` são o que ninguém mais tem. O resto é encanamento.

---

## 9. O que é proibido na arquitetura

Lista curta, para revisão de PR:

1. Adaptador não faz detecção.
2. `Raw` não é serializado, em nenhum formato de saída.
3. `engine/br` não importa nada que faça rede.
4. Nenhum caminho de código manda `Finding.Raw` para fora do processo.
5. Achado com `ValidityInvalid` não sai do núcleo.
6. Config não é recarregada por invocação.
