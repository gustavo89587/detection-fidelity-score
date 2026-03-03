PY=python

.PHONY: help venv install lint test run case01 clean

help:
	@echo "make install   -> install deps"
	@echo "make test      -> run tests"
	@echo "make case01    -> run Case 01 simulation (outputs to ./output)"
	@echo "make clean     -> remove generated outputs"

install:
	$(PY) -m pip install -U pip
	$(PY) -m pip install -r requirements.txt

test:
	$(PY) -m pytest -q

case01:
	$(PY) simulate.py --case case01 --out output/dfs_report.csv

clean:
	@echo "Cleaning output/"
	@rm -rf output/*