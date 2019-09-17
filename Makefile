#
# 
#
.PHONY: test all venv

help:
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-10s\033[0m - %s\n", $$1, $$2} /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)

all: help

##@ Testing

test: checkenv-VIRTUAL_ENV ## Run Python Unit Tests 
	@pip install flexmock
	@python -m unittest discover -b -s test

test-verbose: checkenv-VIRTUAL_ENV ## Run Python Unit Tests - Verbose
	@pip install flexmock
	@python -m unittest discover -b -v -s test

##@ Installation

venv: ## Create virtualenv environment
	virtualenv $@
	@echo "\nVirtualenv created\nexecute the following to activate: $$ source $@/bin/activate\n"

install: checkenv-VIRTUAL_ENV ## Install via pip, ensuring a virtualenv
	@pip install .

install-no-venv: ## Install via pip without ensuring a virtualenv
	@pip install .
	@pip3 install .

##@ Build (for PyPi)

build: checkenv-VIRTUAL_ENV ## Build distro for pypi upload
	@python setup.py sdist bdist_wheel

clean: ## Clean build directories
	rm -rf build
	rm -rf dist
	rm -rf appscale_agents.egg-info
	rm -rf venv

upload: checkenv-VIRTUAL_ENV ## Upload distribution to pypi
	@pip install --user --upgrade twine
	$(info "Uploading to twine")

##@ Utilities

bump-major: ## Bump major version number for appscale-agents
	util/bump_version.sh major

bump-minor: ## Bump minor version number for appscale-agents
	util/bump_version.sh minor

bump-patch: ## Bump patch version number for appscale-agents
	util/bump_version.sh patch

# $* is the environment variable expanded from % in the rule
# $($*) gives the value of the environment variable
checkenv-%:
	$(if $($*), , $(error virtualenv was not detected, exiting))
