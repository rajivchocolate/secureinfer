# SecureInfer

A project to explore LLM inference security by building a secure API layer in Go.

## What This Is

I'm building a secure LLM inference API to understand how AI labs protect their models. The goal is to implement real security controls and test them with simulated attacks.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         SecureInfer                                  │
│                                                                      │
│  ┌──────────┐    ┌──────────────┐    ┌──────────┐    ┌──────────┐   │
│  │  Risk    │    │  Extraction  │    │  Tenant  │    │  Model   │   │
│  │  Scorer  │    │  Detector    │    │ Isolator │    │ Verifier │   │
│  └────┬─────┘    └──────┬───────┘    └────┬─────┘    └────┬─────┘   │
│       │                 │                 │                │         │
│       └─────────────────┴─────────────────┴────────────────┘         │
│                              │                                       │
│                    ┌─────────▼─────────┐                             │
│                    │   Security Gate   │                             │
│                    │ (Allow/Warn/Block)│                             │
│                    └─────────┬─────────┘                             │
│                              │                                       │
│  ┌───────────┐      ┌───────▼───────┐      ┌───────────────┐        │
│  │  SQLite   │◄────►│   Go API      │◄────►│    Ollama     │        │
│  │  (state)  │      │   (Chi)       │      │  (inference)  │        │
│  └───────────┘      └───────────────┘      └───────────────┘        │
│                              ▲                                       │
│                    ┌─────────┴─────────┐                             │
│                    │      Redis        │                             │
│                    │  (rate limiting)  │                             │
│                    └───────────────────┘                             │
└─────────────────────────────────────────────────────────────────────┘
```

## Security Controls

| Component | Purpose |
|-----------|---------|
| **Risk Scorer** | Scores each request 0-100 based on threat signals |
| **Extraction Detector** | Catches attempts to steal the model through systematic queries |
| **Tenant Isolator** | Keeps each user's conversation context separate |
| **Model Verifier** | Detects if model files have been tampered with |

## Running It

```bash
# Local development
ollama serve &
ollama pull phi3.5:3.8b-mini-instruct-q4_K_M
make build && ./secureinfer

# Docker
make docker-up
make ollama-pull

# Kubernetes (Kind)
make k8s-up
make k8s-deploy
make k8s-forward
```

## Attack Demos

```bash
make demo-injection   # Prompt injection attacks
make demo-extraction  # Model extraction simulation
make demo-dos         # Rate limiting test
```

## Project Structure

```
secureinfer/
├── cmd/server/main.go           # Entry point
├── internal/
│   ├── api/                     # HTTP handlers and middleware
│   ├── security/                # Risk scorer, extraction, tenant, verifier
│   ├── inference/               # Ollama client
│   ├── store/                   # SQLite, Redis, memory
│   └── config/                  # Configuration
├── demos/                       # Attack simulations
├── k8s/local/                   # Kubernetes manifests
└── docker/                      # Dockerfile
```

## Stack

- Go with Chi router
- SQLite for persistence
- Redis for caching/rate limiting
- Ollama for local LLM inference
- Kubernetes (Kind for local)

## Resources

- [OWASP Top 10 for LLMs](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Simon Willison on Prompt Injection](https://simonwillison.net/series/prompt-injection/)
- [Stealing ML Models (USENIX '16)](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/tramer)
