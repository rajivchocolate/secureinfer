.PHONY: help build run test lint clean docker-up docker-down k8s-up k8s-down

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
BINARY_NAME=secureinfer
MAIN_PATH=./cmd/server

help:
	@echo "SecureInfer - LLM Security Learning Platform (Go)"
	@echo ""
	@echo "Quick Start:"
	@echo "  make deps        - Download Go dependencies"
	@echo "  make build       - Build the binary"
	@echo "  make run         - Run locally (requires Ollama running)"
	@echo "  make docker-up   - Start all services with Docker Compose"
	@echo ""
	@echo "Development:"
	@echo "  make dev         - Run with hot reload (requires air)"
	@echo "  make test        - Run tests"
	@echo "  make test-v      - Run tests with verbose output"
	@echo "  make lint        - Run linters"
	@echo "  make fmt         - Format code"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build - Build Docker image"
	@echo "  make docker-up    - Start all services"
	@echo "  make docker-down  - Stop all services"
	@echo "  make docker-logs  - View logs"
	@echo ""
	@echo "Kubernetes (Kind):"
	@echo "  make k8s-up      - Create Kind cluster"
	@echo "  make k8s-deploy  - Deploy to Kind"
	@echo "  make k8s-down    - Delete Kind cluster"
	@echo "  make k8s-logs    - View pod logs"
	@echo ""
	@echo "Security Demos:"
	@echo "  make demo-extraction - Run model extraction attack demo"
	@echo "  make demo-injection  - Run prompt injection demo"
	@echo "  make demo-dos        - Run DoS attack demo"
	@echo ""
	@echo "Utilities:"
	@echo "  make ollama-pull - Pull the Phi-3.5 model"
	@echo "  make clean       - Remove build artifacts"

# =============================================================================
# SETUP & BUILD
# =============================================================================

deps:
	$(GOMOD) download
	$(GOMOD) tidy

build: deps
	CGO_ENABLED=1 $(GOBUILD) -o $(BINARY_NAME) $(MAIN_PATH)

build-linux:
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BINARY_NAME)-linux $(MAIN_PATH)

run: build
	./$(BINARY_NAME)

dev:
	@which air > /dev/null || (echo "Installing air..." && go install github.com/cosmtrek/air@latest)
	air

# =============================================================================
# TESTING
# =============================================================================

test:
	$(GOTEST) -race ./...

test-v:
	$(GOTEST) -race -v ./...

test-cover:
	$(GOTEST) -race -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

test-security:
	$(GOTEST) -race -v ./internal/security/...

# =============================================================================
# CODE QUALITY
# =============================================================================

lint:
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run ./...

fmt:
	$(GOCMD) fmt ./...
	@which goimports > /dev/null || go install golang.org/x/tools/cmd/goimports@latest
	goimports -w .

vet:
	$(GOCMD) vet ./...

# =============================================================================
# DOCKER
# =============================================================================

docker-build:
	docker build -t secureinfer:latest -f docker/Dockerfile .

docker-up:
	docker compose up -d
	@echo ""
	@echo "Services starting..."
	@echo "  API:    http://localhost:8000"
	@echo "  Ollama: http://localhost:11434"
	@echo ""
	@echo "Pull model: make ollama-pull"

docker-down:
	docker compose down -v

docker-logs:
	docker compose logs -f

docker-shell:
	docker compose exec api sh

# =============================================================================
# KUBERNETES
# =============================================================================

k8s-up:
	@which kind > /dev/null || (echo "Please install kind: https://kind.sigs.k8s.io/docs/user/quick-start/" && exit 1)
	kind create cluster --name secureinfer --config k8s/kind-config.yaml
	@echo ""
	@echo "Cluster created! Next: make k8s-deploy"

k8s-down:
	kind delete cluster --name secureinfer

k8s-build: docker-build
	kind load docker-image secureinfer:latest --name secureinfer

k8s-deploy: k8s-build
	kubectl apply -f k8s/local/namespace.yaml
	kubectl apply -f k8s/local/
	@echo ""
	@echo "Waiting for pods..."
	kubectl wait --for=condition=ready pod -l app=secureinfer-api -n secureinfer --timeout=180s || true
	@echo ""
	@make k8s-status

k8s-status:
	@echo "=== Pods ==="
	kubectl get pods -n secureinfer
	@echo ""
	@echo "=== Services ==="
	kubectl get svc -n secureinfer

k8s-logs:
	kubectl logs -f -l app=secureinfer-api -n secureinfer

k8s-forward:
	@echo "Forwarding to localhost:8000..."
	kubectl port-forward svc/secureinfer-api 8000:8000 -n secureinfer

k8s-shell:
	kubectl exec -it deploy/secureinfer-api -n secureinfer -- sh

# =============================================================================
# SECURITY DEMOS
# =============================================================================

demo-extraction:
	$(GOCMD) run demos/extraction_attack.go

demo-injection:
	$(GOCMD) run demos/prompt_injection.go

demo-dos:
	$(GOCMD) run demos/dos_attack.go

demo-all: demo-injection demo-extraction demo-dos

# =============================================================================
# OLLAMA
# =============================================================================

ollama-pull:
	@echo "Pulling Phi-3.5 mini model..."
	ollama pull phi3.5:3.8b-mini-instruct-q4_K_M

ollama-run:
	ollama run phi3.5:3.8b-mini-instruct-q4_K_M

ollama-list:
	ollama list

# =============================================================================
# UTILITIES
# =============================================================================

clean:
	rm -f $(BINARY_NAME) $(BINARY_NAME)-linux
	rm -f coverage.out coverage.html
	rm -rf tmp/

# Create test API key
setup-dev-key:
	@echo "Creating test tenant and API key..."
	@curl -s -X POST http://localhost:8000/v1/tenants \
		-H "Content-Type: application/json" \
		-d '{"name":"test-tenant"}' | jq .

# Health check
health:
	@curl -s http://localhost:8000/health | jq .

# API info
info:
	@curl -s http://localhost:8000/ | jq .
