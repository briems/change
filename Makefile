.PHONY: install test

install:
	python -m pip install -r requirements.txt

test:
	pytest -q
