# Agent Deployment

The Linux agent is optional. Manual evidence upload remains supported.

## Server configuration

Set `AGENT_ENROLLMENT_TOKEN` in `.env` to a long random value.

## Agent installation

```bash
cd agent
python -m pip install -e .
```

## Registration

```bash
cybertrace-agent register --server https://server.example --token <enrollment-token> --investigation <id>
```

## Running

```bash
cybertrace-agent run --config /etc/cybertrace/agent.json
```

## Fleet dashboard

Open `http://127.0.0.1:8000/agents`.

## Notes

- Agent tokens are stored only as SHA-256 hashes on the server.
- Collected evidence is preserved and hashed.
- Collection gaps are derived from heartbeats and collection windows.
