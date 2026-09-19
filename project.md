---
okf_version: '0.2'
type: ProjectContext
title: mcp-server-glitchtip — Project Context
description: MCP server enabling LLMs to query issues, stacktraces, and resolve errors in GlitchTip
tags:
- project-context
- mcp-server-glitchtip
- retroactive-reconstruction
status: stable
generated:
  by: agent:mira
  profile: default
  at: '2026-09-19T09:29:19+02:00'
  tools:
  - id: hermes-agent
    role: orchestration-and-authoring
  - id: git
    role: source-retrieval-and-verification
  - id: hermes-kanban
    role: operational-history-retrieval
request_origin:
  requested_by: human:davide-cenzi
  received_at: '2026-09-19T09:25:57+02:00'
  source_kind: telegram
  source_ref: telegram:chat:10081839:session:20260905_121107_8333f1c4:request:retroactive-project-md
  source_url: null
  parent_ref: null
  capture_mode: verbatim
sources:
- resource: file:///Users/operator/Documents/projects/mcp-server-glitchtip
- resource: https://github.com/Crunchy-Bytes-Team/mcp-server-glitchtip.git
- resource: file:///Users/operator/Documents/projects/mcp-server-glitchtip/README.md
---

# Richiesta originaria

> Procedi pure e poi fai un commit in ogni progetto

# Sintesi per operatori

- **Attività:** ricostruito il contesto del progetto `mcp-server-glitchtip` da repository Git, documentazione locale e storico Kanban disponibile.
- **Risultato:** identificati scopo, stack, cronologia, stato del checkout e attività operative rintracciabili.
- **Dubbi o domande:** Nessuno; le informazioni non dimostrabili sono indicate come non verificate.

# Interpretazione operativa

- **Obiettivo:** creare una scheda retroattiva e agent-readable del progetto.
- **Output richiesto:** `project.md` versionato nel repository.
- **Vincoli espliciti:** ricostruire dalle evidenze disponibili e creare un commit dedicato senza includere modifiche concorrenti.

# Identità del progetto

- **Nome rilevato:** mcp-server-glitchtip
- **Directory canonica:** `/Users/operator/Documents/projects/mcp-server-glitchtip`
- **Descrizione rilevata:** MCP server enabling LLMs to query issues, stacktraces, and resolve errors in GlitchTip
- **README sorgente:** `README.md`

# Repository

- **Remote origin:** `https://github.com/Crunchy-Bytes-Team/mcp-server-glitchtip.git`
- **Branch corrente al rilevamento:** `feature/security-and-docker`
- **Branch predefinito remoto:** non determinato
- **HEAD prima della generazione:** `653bbe5a4d26d7b62e55d58fda32ab2bcbf455f8`
- **Working tree preesistente:** clean

# Stack e superfici tecniche

- Python
- Docker Compose

- **Manifest rilevati:** `Dockerfile`, `docker-compose.yml`, `pyproject.toml`
- **Workflow CI:** nessuno sotto `.github/workflows/`

# Cronologia Git

- **Commit totali raggiungibili da HEAD:** 2
- **Primo commit raggiungibile:** 2026-03-15T23:20:33+01:00
- **Ultimo commit:** 2026-07-08T17:58:18+02:00

## Contributor principali

- Davide Cenzi <link82@gmail.com> — 1 commit
- Edward <support@crunchy-bytes.com> — 1 commit

## Commit recenti

- `653bbe5` — 2026-07-08T17:58:18+02:00 — fix: resolve issues via project-scoped GlitchTip API
- `cc43f14` — 2026-03-15T23:20:33+01:00 — Temporarily disable IP whitelist check in server.py to resolve Docker compatibility issues

# Storico operativo Kanban

Nessun task collegato in modo deterministico tramite workspace o percorso assoluto. Questo non prova l’assenza di lavorazioni storiche.

# Stato e limiti della ricostruzione

- **Stato documentale:** stable: checkout pulito al momento del rilevamento.
- Lo storico Git descrive solo attività committate; lavoro locale, meeting e operazioni esterne possono non comparire.
- Il collegamento Kanban usa corrispondenze deterministiche sul workspace/percorso; task privi di path esplicito possono non essere associati.
- Descrizioni e stack sono estratti da file versionati; nessuna capacità di produzione è assunta senza evidenza.

# Aggiornamento futuro

Aggiornare questo documento quando cambiano scopo, repository canonico, stack, deployment, ownership o decisioni operative sostanziali. Conservare fatti verificati separati da ipotesi e piani.
