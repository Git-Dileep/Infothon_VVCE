# Windows without make? Run the python commands directly (see README).
setup:
	pip install -r requirements.txt
fixture:
	python -m patchpilot.ingest fixture
test:
	python -m pytest -q
app:
	streamlit run app.py
backtest:
	python -m patchpilot.backtest
eval:
	python -m patchpilot.eval
