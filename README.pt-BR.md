<div align="center">

<img src="assets/vedei-logo.svg" width="600" alt="vedei — o que não deve sair, não sai">

**Encontra e valida dados sensíveis brasileiros e segredos vazados — offline, por dígito verificador, antes de chegarem ao seu log, ao seu CI ou ao contexto do seu agente de IA.**

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.27-00ADD8.svg)](go.mod)
[![CI](https://github.com/mkmuniz/vedei/actions/workflows/ci.yml/badge.svg)](https://github.com/mkmuniz/vedei/actions/workflows/ci.yml)

[English](README.md)

</div>

---

## Estado

**M4 concluído — a CLI, o CI e o caminho de agente funcionam.** `vedei scan`, `vedei git` e `vedei diff` reportam em tabela, JSON, JSONL ou SARIF; a GitHub Action publica no Code Scanning; o `vedei hook` mantém segredos fora do contexto do agente a **8,4 ms p95**; `vedei transcript scan` e `scrub` cuidam do que já vazou. A calibração multilíngue de falso positivo é o M5, e é o que mais tende a incomodar até lá — veja a nota abaixo do roadmap.

## Experimente

```bash
go install github.com/mkmuniz/vedei/cmd/vedei@latest
go install github.com/mkmuniz/vedei/cmd/vedei-hook@latest
```

```bash
vedei scan .                        # uma árvore, respeitando .gitignore
vedei scan . --format sarif -o vedei.sarif
vedei git                           # o histórico, inclusive arquivos apagados
vedei diff --staged                 # o que está prestes a ser commitado
vedei transcript scan               # o que já vazou nos seus logs de sessão

echo 'cpf 529.982.247-25' | vedei stream
# cpf ***.***.***-25 [vedei: cpf redacted]   (exit 3)
```

Os códigos de saída são distintos de propósito: **0** limpo, **3** achados, **1** a varredura em si falhou, e 1 tem precedência sobre 3. Um pipeline que não distingue vazamento de varredura quebrada vai ler erro de permissão como execução limpa.

No CI:

```yaml
- uses: mkmuniz/vedei@v1
  with:
    mode: diff          # só o que mudou; "history" num agendamento
```

## Silenciando o que é deliberado

O `.vedeiignore` aceita o fingerprint do achado, derivado do tipo e do valor normalizado e **nunca da localização** — então a entrada sobrevive ao arquivo ser movido ou renomeado. O arquivo deste repositório é o [`.vedeiignore`](.vedeiignore): 71 achados, 21 fingerprints, cada um com o motivo escrito ao lado. Nada é silenciado por caminho, de propósito. Silenciar `*_test.go` inteiro também silenciaria uma credencial de verdade commitada num teste, que é um lugar onde credencial de verdade acaba indo.

Depois ligue o hook no seu agente: [`hooks/`](hooks/). São dois binários, e é essa separação que deixa o hook rápido — o `vedei` carrega 417 regras de segredo, o `vedei-hook` tem 5 MB e só conversa com o daemon.

## O que detecta

| Dado | Validação offline | Algoritmo |
|---|:---:|---|
| **CPF** | ✅ | Módulo 11, dois DVs; rejeita sequências repetidas |
| **CIN** | ✅ | Usa o CPF como número nacional — mesma validação |
| **CNPJ** numérico | ✅ | Módulo 11, pesos `5,4,3,2,9,8,7,6,5,4,3,2` |
| **CNPJ** alfanumérico | ✅ | Módulo 11 com `ASCII − 48` nas letras — **primeiro emitido em 31/07/2026** ([Receita Federal](https://www.gov.br/receitafederal/pt-br/assuntos/noticias/2026/julho/receita-federal-gera-o-primeiro-cnpj-em-formato-alfanumerico)) |
| **CNH** | ✅ | Módulo 11, variante de 11 dígitos |
| **PIS / NIS / NIT** | ✅ | Módulo 11, pesos `3,2,9,8,7,6,5,4,3,2` |
| **Título de eleitor** | ✅ | Dois DVs, módulo 11, com código de UF |
| **CNS** (cartão SUS) | ✅ | Soma ponderada ≡ 0 (mod 11) |
| **PAN de cartão** | ✅ | Luhn + faixa de BIN |
| **Chave Pix** | ✅ | Por tipo: CPF/CNPJ, e-mail, telefone, EVP (UUID v4) |
| **E2EID de Pix** | ✅ | `E` + ISPB(8) + `AAAAMMDDHHMM` + 11 alfanuméricos |
| **Agência / conta** | ⚠️ | DV varia por instituição |
| **RG** | ❌ | **Sem padrão nacional.** Só heurística contextual, confiança baixa |
| **Segredos** (463 regras) | via provedor | Delegado ao [betterleaks](https://github.com/betterleaks/betterleaks) |

A maioria dos detectores casa CNPJ com `\d{14}`. Isso está errado desde julho de 2026.

Base de ISPB do [`guibranco/BancosBrasileiros`](https://github.com/guibranco/BancosBrasileiros) — mais de 400 instituições, atualizada diariamente.

## Onde roda

| Superfície | O que faz | Estado |
|---|---|---|
| **Contexto de agente de IA** | Hook `PostToolUse` para Claude Code e Codex. O `cat .env` chega tarjado ao modelo | 🎯 MVP |
| **Transcripts de agente** | Audita o que já vazou para `~/.claude/projects/*.jsonl` | 🎯 MVP |
| **CI/CD** | CLI, GitHub Action, SARIF, pre-commit, pre-receive | planejado |
| **Runtime da aplicação** | `slog.Handler` e middleware HTTP que tarjam antes de escrever | planejado |
| **Observabilidade** | Processador de OpenTelemetry Collector para log e trace | planejado |

## Por que existe

Detecção de segredo é problema resolvido e concorrido — betterleaks tem 463 regras, kingfisher 1.051. Reconstruir esse corpus é perder. Então o vedei **importa o betterleaks** (MIT) e concentra o esforço onde as ferramentas globais são mais fracas: **dado sensível brasileiro**, validado por dígito verificador em vez de casado por formato — CPF, CNPJ inclusive o alfanumérico, CNH, chave Pix e E2EID, PAN de cartão com bandeiras brasileiras. E aplica o controle na fronteira por onde o dado sai: o contexto do agente, a execução de CI, a linha de log. Um binário Go, sem runtime, sem rede.

A segunda razão é arquitetural. O betterleaks valida segredo perguntando ao provedor por HTTP, o que exige rate limiter, orçamento de timeout e cuidado com o destino das requisições. Dado pessoal brasileiro não funciona assim: CPF é módulo 11, cartão é Luhn, chave Pix é o tipo dela. **Tudo offline.** Sem rede, sem limite de vazão, sem superfície de SSRF. Mais simples e mais seguro, não só diferente.

### Por que o transcript importa

Um `.env` tem proteções — gitignore, permissão de arquivo, cofre. O `~/.claude/projects/*.jsonl` não tem nenhuma: texto puro, sem criptografia, sem rotação, sem expiração, sem ferramenta de segurança vigiando. Quem lê o disco — malware, notebook roubado, backup exfiltrado — lê todo segredo que o agente já tocou.

O vedei reduz o que entra ali e mostra o que já entrou. Não substitui criptografia de disco.

Documentado no próprio repositório do Claude Code: [#44868](https://github.com/anthropics/claude-code/issues/44868), [#50014](https://github.com/anthropics/claude-code/issues/50014), [#95680](https://github.com/anthropics/claude-code/issues/95680).

## O que "validar" significa aqui

| | Segredo | Dado pessoal |
|---|---|---|
| Responde | **Está vivo?** | **É estruturalmente real?** |
| Mecanismo | HTTP ao provedor | Aritmética local |
| Rede | obrigatória | **nenhuma** |
| Latência | 50–500 ms | microssegundos |
| Próximo passo | revogar / rotacionar | tarjar / remover |

**A linha que o vedei não atravessa:** dado pessoal é validado pela *estrutura*, nunca consultando base oficial. O vedei diz que `123.456.789-09` é um CPF estruturalmente válido. Nunca de quem.

## Princípios de projeto (inegociáveis)

1. **Um valor detectado nunca chega a um modelo de linguagem.** Garantido por teste de CI bloqueante.
2. **Dado pessoal é validado estruturalmente, nunca contra base oficial.**
3. **Saída de modelo é sinal, nunca filtro.** Pode reordenar fila; não pode descartar achado.
4. **Fail-open na tarja, fail-closed no relatório.** Quebrar a sessão é pior que deixar de tarjar; reportar "limpo" com scan quebrado é pior que build vermelho.
5. **Códigos de saída distintos:** `0` limpo, `3` achou, `1` erro.
6. **Zero falso positivo em valor estruturalmente inválido.** Se o DV não fecha, não é CPF.
7. **Limiares calibrados por idioma.** Heurística afinada para inglês erra em código em português.

Registros completos em [`docs/adr/`](docs/adr/).

## Roadmap

| | Milestone | Estado |
|---|---|---|
| M0 | Fundação | ✅ |
| M1 | Detectores BR + validação offline | ✅ |
| M2 | Motor de segredos via betterleaks | ✅ |
| M3 | **MVP — superfície de IA** | ✅ |
| M4 | CLI, CI/CD, SARIF, scrub de transcript | ✅ |
| M5 | Corpus multilíngue + calibração pt-BR | 🚧 |
| M6 | SDK de runtime | ⬜ |
| M7 | Camada de IA | ⬜ |
| M8 | Coletor de observabilidade | ⬜ |
| M9 | Validação de segredo + allowlist de destino | ⬜ |
| M10 | v1.0 | ⬜ |

Features, passo a passo, estratégia de teste e critério de saída por etapa: [`MILESTONES.md`](MILESTONES.md). Desenho de componentes e orçamentos: [`ARCHITECTURE.md`](ARCHITECTURE.md).

**Sobre o M5.** O betterleaks filtra candidatos por razão de token BPE contra um dicionário de 33.775 palavras **em inglês** e limiar fixo de 2,5. Medido com o tokenizador que ele mesmo embute: `defaultpassword` dá 7,50 e é corretamente descartado; `senhapadrao` dá 2,20 e é reportado como segredo. Segredos reais ficam em 1,0–1,6. Em inglês a separação é confortável; em português quase some. O M5 transforma isso em corpus versionado e métrica cobrada no CI.

## Estrutura do projeto

```
detect/br/        # o nucleo: validadores puros, zero dependencia
detect/engine.go  # a interface Engine — isola a API v2 do betterleaks
engine/secrets/   # betterleaks embrulhado atras dessa interface
redact/           # tarja preservando formato
report/           # JSON, JSONL, SARIF
scan/             # caminhador de diretorio, matcher de gitignore, historico git
report/           # tabela, JSON, JSONL, SARIF
stream/           # stdin -> stdout, o caminho do MVP
daemon/           # servidor e cliente do socket Unix — o caminho de 8,4 ms
transcript/       # leitor de log de sessao de agente
hooks/            # hooks de agente, hooks de git, units de launchd e systemd
corpus/           # harness rotulado de precision/recall (make corpus)
```

## O nome

**Надзор** (*vedei*) é "supervisão" ou "fiscalização" em russo — a palavra usada para supervisão regulatória. É `dozor` (a ronda) com o prefixo `nad-` (sobre, acima).

Uma ferramenta que inspeciona o que passa por uma fronteira e aplica uma regra sobre isso não é um guarda. É fiscalização.

## Contribuir · Segurança · Licença

- Detector novo? Leia [`CONTRIBUTING.md`](CONTRIBUTING.md) — teste de propriedade é obrigatório em código de dígito verificador.
- Achou vulnerabilidade? [`SECURITY.md`](SECURITY.md). Não abra issue pública.
- [MIT](LICENSE), a mesma do betterleaks.
