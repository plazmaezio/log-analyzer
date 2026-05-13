# LogAnalyser

Ferramenta em C para análise e classificação de logs de sistemas e servidores web. Suporta múltiplos formatos de log e classifica eventos por tipo (segurança, performance, tráfego, erro) e severidade.

---

## Estrutura do Projeto

```
LogAnalyser/
├── src/                        # Código-fonte principal
│   ├── log_parser.h            # Definições de estruturas e protótipos dos parsers
│   ├── log_parser.c            # Implementação dos parsers de log
│   ├── event_classifier.h      # Definições de tipos de eventos e protótipos do classificador
│   ├── event_classifier.c      # Implementação da lógica de classificação de eventos
│   ├── test_parsers.c          # Testes unitários para os parsers
│   ├── test_classifier.c       # Testes unitários para o classificador de eventos
│   └── Makefile                # Sistema de build (compatível Linux/macOS)
│
├── generators/                 # Geradores de dados sintéticos para testes
│   ├── generate_apache_logs.c  # Gerador de logs no formato Apache Combined Log
│   ├── generate_json_logs.c    # Gerador de logs estruturados em JSON
│   ├── generate_syslog.c       # Gerador de logs no formato Syslog (RFC 3164)
│   └── generate_nginx_error.c  # Gerador de logs de erro do Nginx
│
├── datasets/                   # Datasets de teste gerados automaticamente (criados pelo Makefile)
│   ├── apache/                 # Logs Apache gerados
│   ├── json_logs/              # Logs JSON gerados
│   ├── syslog/                 # Logs Syslog gerados
│   └── nginx/                  # Logs Nginx gerados
│
└── docs/                       # Documentação
    └── eventos.md              # Guia completo de classificação de eventos
```

---

## Módulos

### `src/log_parser` — Parsers de Log

Responsável por fazer o parsing das quatro fontes de log suportadas, convertendo linhas de texto em estruturas C tipadas.

| Formato | Estrutura | Função de parsing |
|---|---|---|
| Apache Combined Log | `ApacheLogEntry` | `parse_apache_log()` |
| JSON Structured Log | `JSONLogEntry` | `parse_json_log()` |
| Syslog (RFC 3164) | `SyslogEntry` | `parse_syslog()` |
| Nginx Error Log | `NginxErrorEntry` | `parse_nginx_error()` |

Cada entrada captura campos relevantes: IP de origem, timestamp, nível de severidade, serviço, mensagem, entre outros específicos de cada formato.

---

### `src/event_classifier` — Classificador de Eventos

Analisa as entradas já processadas pelos parsers e classifica cada evento com um ou mais tipos (via bitmask) e um nível de severidade.

**Tipos de evento (`EventType`):**

| Flag | Valor | Descrição |
|---|---|---|
| `EVENT_SECURITY` | `1 << 0` | Autenticação, acessos negados, ataques |
| `EVENT_PERFORMANCE` | `1 << 1` | Timeouts, erros de servidor, crashes |
| `EVENT_TRAFFIC` | `1 << 2` | Padrões de tráfego e utilização |
| `EVENT_ERROR` | `1 << 3` | Erros aplicacionais |
| `EVENT_NORMAL` | `1 << 4` | Operação normal |

**Níveis de severidade:**

| Nível | Valor | Descrição |
|---|---|---|
| INFO | 0 | Operação normal |
| LOW | 1 | Anomalia menor |
| MEDIUM | 2 | Requer atenção |
| HIGH | 3 | Ação necessária |
| CRITICAL | 4 | Falha crítica |

**Modos de análise (`AnalysisMode`):** Os modos `MODE_SECURITY`, `MODE_PERFORMANCE`, `MODE_TRAFFIC` e `MODE_FULL` permitem filtrar eventos por categoria usando OR bitwise.

---

### `generators/` — Geradores de Datasets

Programas C independentes que produzem logs sintéticos realistas para testes. Recebem como argumento o número de linhas/ficheiros a gerar e escrevem o output para `stdout` ou para uma pasta.

| Gerador | Binário compilado | Output |
|---|---|---|
| `generate_apache_logs.c` | `gen_apache` | `datasets/apache/` |
| `generate_json_logs.c` | `gen_json` | `datasets/json_logs/` |
| `generate_syslog.c` | `gen_syslog` | `datasets/syslog/` |
| `generate_nginx_error.c` | `gen_nginx` | `datasets/nginx/` |

---

### `docs/eventos.md` — Guia de Classificação

Documentação detalhada com a lógica de classificação para cada formato de log, incluindo tabelas de referência para status codes HTTP, padrões de ataque (SQL Injection, XSS, Path Traversal), mapeamento de severidade Syslog e exemplos práticos de cenários reais (ataques de força bruta, scans de vulnerabilidades, cascatas de falhas de performance).

---

## Build e Utilização

O Makefile encontra-se em `src/`. Todos os comandos devem ser executados a partir dessa pasta.

```bash
cd src/

make              # Compila tudo (parsers, classificador, geradores)
make datasets     # Gera datasets de teste (~1 MB)
make run-tests    # Compila e executa a suite de testes
make clean        # Remove binários compilados
make help         # Lista todos os targets disponíveis
```

Para gerar datasets maiores (útil para testes de performance):

```bash
make datasets-large   # Gera datasets grandes (~15 MB)
```

**Requisitos:** GCC, Make, suporte a POSIX threads (`-pthread`). Compatível com Linux e macOS.
