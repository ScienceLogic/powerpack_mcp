SERVICE_NAME ?= powerpack-mcp-dev
SHELL_CMD    ?= /bin/bash
EDITABLE     ?= 1

COMPOSE_FILES := -f docker-compose.yml
ifeq ($(EDITABLE),1)
COMPOSE_FILES += -f docker-compose.editable.yml
endif
COMPOSE      := docker compose $(COMPOSE_FILES)
COMPOSE_EXEC := $(COMPOSE) exec $(SERVICE_NAME)

ifneq (,$(wildcard .env))
include .env
export
endif

HAS_UV   := $(shell command -v uv 2>/dev/null)
cmd_test := uv run pytest
cmd_typecheck := bash -c "uv run mypy && uv run pyright"
cmd_lint := bash -c "uv run ruff format --check && uv run ruff check . && uv run mypy && uv run pyright"
cmd_prek := uv run prek --all-files --stage=manual

.PHONY: announce-docker-fallback lint test typecheck prek dev-build dev-up dev-down dev-shell dev-exec dev-copy-coverage dev-test dev-typecheck dev-lint dev-prek

announce-docker-fallback:
	@echo ''
	@echo '=========================================='
	@echo '     Falling back to Dockerized run '
	@echo '=========================================='
	@echo '                      ##         .'
	@echo '                ## ## ##        =='
	@echo '             ## ## ## ## ##    ==='
	@echo '        /"""""""""""""""""\___/ ==='
	@echo '   ~~~ {~~ ~~~~ ~~~ ~~~~ ~~~ ~ /  ===- ~~~'
	@echo '        \______ o           __/'
	@echo '          \    \         __/'
	@echo '           \____\_______/'
	@echo '=========================================='
	@echo ''

ifneq ($(HAS_UV),)

lint test typecheck prek: %:
	$(cmd_$*)
else

lint test typecheck prek: %: announce-docker-fallback dev-up
	$(COMPOSE_EXEC) $(cmd_$*)
endif


dev-build:
	$(COMPOSE) build $(SERVICE_NAME)

dev-up: dev-build
	$(COMPOSE) up -d

dev-down:
	$(COMPOSE) down --volumes --remove-orphans

dev-shell: dev-up
	$(COMPOSE_EXEC) $(SHELL_CMD)

dev-exec:
ifndef CMD
	$(error CMD is required. Usage: make dev-exec CMD='uv run ...')
endif
	$(COMPOSE_EXEC) $(CMD)

dev-copy-coverage:
	$(COMPOSE) cp $(SERVICE_NAME):/app/cov_report.xml cov_report.xml
dev-test dev-typecheck dev-lint dev-prek: dev-%: dev-up
	$(COMPOSE_EXEC) $(cmd_$*)
