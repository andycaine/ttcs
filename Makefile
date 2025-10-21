PYTHON_FILES := $(shell find ttcs -name '*.py')
VERSION := $(shell uv version --short)
TEMPLATE_DIR := templates

$(TEMPLATE_DIR):
	mkdir -p $@

templates/network-v$(VERSION).yaml: $(PYTHON_FILES) $(TEMPLATE_DIR)
	uv run python -m ttcs.network > $@

templates/data-v$(VERSION).yaml: $(PYTHON_FILES) $(TEMPLATE_DIR)
	uv run python -m ttcs.data > $@

templates/application-v$(VERSION).yaml: $(PYTHON_FILES) $(TEMPLATE_DIR)
	uv run python -m ttcs.application > $@

test: templates/network-v$(VERSION).yaml templates/data-v$(VERSION).yaml templates/application-v$(VERSION).yaml
	cfn-lint templates/*

build: test

clean:
	rm -rf templates
