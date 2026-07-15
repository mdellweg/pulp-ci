.PHONY: format
format:
	ruff format
	ruff check --fix

.PHONY: lint
lint:
	ruff format --check --diff
	ruff check --diff --output-format concise
	ty check --output-format concise
	@echo "🙊 Code 🙈 LGTM 🙉 !"
