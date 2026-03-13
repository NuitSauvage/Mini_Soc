# MiniSOC Copilot – GenAI-Assisted Incident Triage Prototype

MiniSOC Copilot is a prototype tool designed to assist Security Operations Center (SOC) analysts during incident triage.

The system ingests multiple sources of logs (email reports, authentication events, and endpoint activity), correlates suspicious events into incidents, and uses GenAI to generate analyst-friendly summaries and suggested investigation steps.

The goal is not to automate security decisions but to reduce analyst triage time and improve incident visibility.

## Project Structure

MiniSOC/
│
├── data/
│   ├── raw/
│   ├── HDFS_2k.log
│   ├── email_reports.csv
│   ├── auth_logs.csv
│   └── endpoint_logs.csv
│
│
├── notebooks/
│   └── minisoc_analysis.ipynb
│
├── src/
│   ├── minisoc_app.py
│   ├── utils.py
│   ├── llm_helper_local.py
│   └── llm_helper_local_constrained_reasoning.py
│
├── requirements.txt
├── README.md
└── .gitignore

- `data/` contains simulated SOC logs
- `minisoc_analysis.ipynb` explains the analysis pipeline
- `utils.py` is a simple Streamlit interface for incident triage

## Environment setup


Create a virtual environment named **minosoc-env**:
</bash  python -m venv minosoc-env>

Mac/Linux:
</bash source venv/bin/activate>

OR

Windows:
</bash minosoc-env\Scripts\activate>

Install dependencies:
</bash pip install -r requirements.txt>

## Run the Analysis Notebook
</bash jupyter lab minisoc_analysis.ipynb>

The notebook demonstrates:

1. Log ingestion
2. Suspicious pattern detection
3. Event correlation
4. Incident creation
5. GenAI-assisted incident summarization

## Run the Demo App

streamlit run app.py

The app displays:

- Incident queue
- Event timeline
- AI-generated incident summary
- Suggested investigation actions

## Example incident workflow

1. Suspicious email reported
2. Multiple failed logins
3. Login success from unusual location
4. PowerShell execution detected

MiniSOC correlates these events into a single incident and generates a summary for analysts.

## GenAI considerations

The system uses GenAI to assist analysts with:

- alert summarization
- incident explanation
- suggested investigation steps

However, AI output should always be treated as decision support and validated by a human analyst.

Potential risks include hallucinations, prompt injection through attacker-controlled log content, and confidentiality concerns.

## Future improvements

- integrate real SIEM log formats
- add anomaly detection models
- connect to real-time log streams
- implement alert prioritization
