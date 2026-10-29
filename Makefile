PY ?= python
export PYTHONPATH := src

setup:            ## install deps and fetch public knowledge bases
	pip install -r requirements.txt
	$(PY) scripts/fetch_attack_stix.py
	$(PY) scripts/fetch_sigmahq.py

core:             ## steps 1-4
	$(PY) -m ai_soc.orchestration.pipeline --stages core

all:              ## steps 1-7 + labels + evaluation (offline, mock analyst)
	$(PY) -m ai_soc.orchestration.pipeline --stages all

experiments:      ## E0-E8 + paper tables
	$(PY) experiments/run_all.py

test:
	$(PY) -m pytest -q

dashboard:
	streamlit run app/dashboard.py
