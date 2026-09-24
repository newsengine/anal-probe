# MITRE ATLAS coverage

How VibeTesting Agent's `atlas` category maps to the [MITRE ATLAS matrix](https://atlas.mitre.org/matrices/ATLAS-matrix)
— the adversarial-threat framework for AI/ML systems.

ATLAS techniques mostly assume interaction with the model/training pipeline. A **black-box, unauthenticated
scanner** can only reach the subset that is observable from a deployed AI web app. We test that subset
honestly and say plainly what is out of scope, rather than claiming full matrix coverage.

The `atlas` checks run **only when an AI/LLM surface is detected** on the homepage (chat/inference markers
or endpoints), so a non-AI app is never false-probed (`atlas.none`).

## What we test (black-box)

| VTA check | ATLAS technique | Tactic | Default | What it detects |
| --- | --- | --- | --- | --- |
| `atlas.model-artifact*` | AML.T0044 Full ML Model Access | ML Model Access | on | Model weights/artifacts (`.gguf/.safetensors/.onnx/.pt/.pkl/.bin`, `/models/`) downloadable from the webroot. |
| `atlas.inference-open` | AML.T0040 ML Model Inference API Access | ML Model Access | on | An inference/LLM endpoint is reachable — confirm it requires auth + rate limiting. |
| `atlas.model-enum*` | AML.T0040 | ML Model Access / Discovery | on | An OpenAI/Ollama/vLLM-compatible server lists its model catalogue (`/v1/models`, `/api/tags`) unauthenticated. |
| `atlas.data-leak*` | AML.T0057 LLM Data Leakage · AML.T0055 Unsecured Credentials | Exfiltration / Credential Access | on | An AI endpoint/error exposes the system prompt, model config, or a provider API key. |
| `atlas.cost-dos*` | AML.T0034 Cost Harvesting · AML.T0029 Denial of ML Service | Impact | opt-in `--rate-limit-scan` | An expensive AI route is not throttled (budget-DoS / model-DoS). |
| `atlas.prompt-injection*` | AML.T0051 LLM Prompt Injection | Initial Access / Execution | opt-in `--ai-probe` | A benign canary instruction overrides the system prompt on a chat endpoint. |

Loud probes (cost burst, prompt-injection payload) are opt-in so the default scan stays polite and
non-destructive (white-hat: identify, never damage).

## Deliberately out of scope (needs model internals, auth, or multi-step interaction)

These ATLAS techniques cannot be judged by a source-less, unauthenticated black-box scan and are **not**
claimed — they belong to an authenticated/agentic tester with model access:

- **AML.T0043 Craft Adversarial Data / AML.T0042 Verify Attack** — needs iterative model querying + labels.
- **AML.T0020 Poison Training Data / AML.T0059 Erode Dataset Integrity** — needs access to the training/RAG ingestion pipeline.
- **AML.T0024 Exfiltration via ML Inference API (model inversion/extraction)** — needs a large authenticated query budget against the model.
- **AML.T0018 Backdoor ML Model / AML.T0031 Evade ML Model** — needs model internals or a controlled test harness.
- **AML.T0025 Exfiltration via Cyber Means / AML.T0035 ML Artifact Collection** — post-compromise, not observable pre-auth.
- **Prompt-injection *impact* chains** (tool/agent abuse, data exfiltration via an agent's tools) — needs an authenticated session and privileged tool access to observe.

## Roadmap

Tracked in [#37](https://github.com/newsengine/anal-probe/issues/37): expand to any further black-box-reachable
techniques (e.g. insecure-output-handling where observable) and keep this matrix current. Authenticated /
model-access techniques are handled by the companion authenticated tester, not this scanner.
