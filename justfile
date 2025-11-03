default: install-dev

tests: venv install-dev
  #!/bin/sh
  source .venv/bin/activate
  .venv/bin/pytest -s -vvv tests/

venv:
  #!/bin/bash
  uv venv 
  source .venv/bin/activate

install: venv
  @echo venv
  uv pip install -e .

install-dev: venv
  @echo venv
  uv pip install -e .[dev]

pip *args:
  @echo venv
  uv pip {{args}}

ruff-check:
  ruff check
  ruff check --select I --fix .

ruff-format:
  ruff format --line-length=120 src/

run: 
  #!/bin/bash
  source .venv/bin/activate
  set +o history
  read -s PALO_USERNAME
  read -s PALO_PASSWORD
  read -s CISCO_USERNAME
  read -s CISCO_PASSWORD
  export PALO_USERNAME; export PALO_PASSWORD; export CISCO_USERNAME; export CISCO_PASSWORD
  network-exporter --devmode

build: ruff-check ruff-format tests
  #!/bin/sh
  export DOCKER_BUILDKIT=1
  version=$(sed -rn 's/version = \"(.*)\"/\1/p' pyproject.toml)
  docker build . --platform linux/amd64 -t network-exporter:${version} 
