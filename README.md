# oss_llm_security_gateway

A self-hosted security gateway for LLM applications that inspects prompts and files before they are sent to an upstream model provider.
The project is designed to sit between an OpenAI-compatible client such as Open WebUI and an OpenAI-compatible proxy such as LiteLLM:
Open WebUI
    |
    v
OSS LLM Security Gateway :8080
    |
    |  ALLOW
    v
LiteLLM :4000
    |
    v
Gemini / OpenAI / Anthropic / other LiteLLM backends
If a request violates the configured security policy, the gateway returns HTTP 403 and does not forward the request to LiteLLM.
[!IMPORTANT]
This repository is an MVP/reference implementation, not a certified DLP product. Review the threat model, detection rules, deployment topology, and false-positive/false-negative behavior before using it in production.

Why this project exists
LLM frontends are often connected directly to cloud model APIs. That creates several security risks:
- accidental disclosure of personal data;
- API keys, tokens, passwords, and private credentials pasted into prompts;
- disclosure of internal or commercially sensitive information;
- prompt-injection and jailbreak attempts;
- malicious or sensitive content embedded in uploaded documents;
- direct bypass of UI-level filters when the model proxy remains reachable.
This gateway moves the enforcement point into the network path so that security checks remain active even if the UI layer is changed or bypassed.
Features
OpenAI-compatible gateway
The gateway currently proxies:
- GET /v1/models
- POST /v1/chat/completions
- POST /v1/responses
Authorization headers are forwarded to LiteLLM, so existing LiteLLM virtual keys can continue to be used.
PII detection
PII detection uses Presidio custom recognizers with additional validation for several Russian identifiers.
Currently covered:
- email addresses;
- Russian phone numbers;
- Russian passport numbers;
- SNILS;
- INN;
- payment card numbers;
- person names via Natasha when enabled in policy.
Checksum validation is applied where supported to reduce obvious false positives.
Secret detection
Gitleaks scans prompt content for credentials and secrets such as:
- API keys;
- access tokens;
- private credentials;
- service secrets;
- other secret formats supported by Gitleaks rules.
The gateway sends content to the local Gitleaks process through stdin. Prompt contents do not need to be written to a Git repository.
Commercially sensitive information
The included policy engine supports organization-specific rules for:
- confidentiality markings;
- internal project names;
- protected customer/system/product identifiers;
- combinations of commercial-risk terms.
Example policy:
blocked_markings:
  - "Confidential"
  - "Strictly Confidential"
  - "Internal Only"
  - "Commercial Secret"

protected_terms:
  - "PROJECT-AURORA"
  - "RND-147"
  - "PHOENIX-INTERNAL"

commercial_terms_min_hits: 2
commercial_terms:
  - "margin"
  - "cost price"
  - "financial forecast"
  - "unpublished pricing"
  - "customer database"
  - "contract terms"
  - "source code"
  - "internal architecture"
  - "roadmap"
You should replace the example terms with rules that reflect your own information-classification policy.
Prompt-injection heuristics
The gateway includes basic rule-based detection for common English and Russian prompt-injection patterns, including attempts to:
- ignore previous instructions;
- reveal system/developer prompts;
- enable jailbreak/DAN-style modes;
- exfiltrate credentials or secrets.
This is intentionally treated as one security layer, not as a complete prompt-injection defense.
File scanning
Files can be scanned through:
POST /v1/scan/file
The current file pipeline is:
Uploaded file
    |
    v
Size limit
    |
    v
ClamAV
    |
    v
Apache Tika MIME detection
    |
    +--> blocked executable/archive type -> BLOCK
    |
    v
Apache Tika text extraction
    |
    v
PII / secrets / policy / injection checks
    |
    v
ALLOW or BLOCK
Fail-closed behavior
With FAIL_CLOSED=true, failures in critical security components cause the request to be blocked instead of silently bypassing inspection.
Architecture
                           +--------------------+
                           |     Open WebUI     |
                           +---------+----------+
                                     |
                           OpenAI-compatible API
                                     |
                                     v
                    +-------------------------------+
                    |    OSS LLM Security Gateway   |
                    |                               |
                    |  Presidio  -> PII             |
                    |  Natasha   -> optional NER    |
                    |  Gitleaks  -> secrets         |
                    |  Rules     -> trade secrets   |
                    |  Rules     -> prompt injection|
                    |  ClamAV    -> malware         |
                    |  Tika      -> file extraction |
                    +---------------+---------------+
                                    |
                              ALLOW only
                                    |
                                    v
                           +------------------+
                           |     LiteLLM      |
                           +--------+---------+
                                    |
                                    v
                         Upstream model provider
The security gateway performs inspection locally. It does not call an external SaaS DLP service for classification.
Project structure
.
├── docker-compose.security.yml
├── openwebui_filter.py
├── .env.example
├── README.md
└── security-gateway/
    ├── app.py
    ├── policy.yaml
    ├── requirements.txt
    └── Dockerfile
Quick start
Requirements
- Docker Engine or Docker Desktop;
- Docker Compose v2;
- a reachable LiteLLM instance;
- an upstream model already configured in LiteLLM.
1. Start the security stack
docker compose -f docker-compose.security.yml up -d --build
Check container status:
docker compose -f docker-compose.security.yml ps
The expected services are:
security-gateway
tika
clamav
2. Check gateway health
The default compose file publishes the gateway only on localhost:
curl http://127.0.0.1:8080/healthz
Expected response:
{"status":"ok"}
PowerShell:
Invoke-RestMethod http://127.0.0.1:8080/healthz
3. Configure the LiteLLM upstream
By default, the compose configuration uses:
LITELLM_BASE_URL=http://host.docker.internal:4000
This is convenient when LiteLLM is exposed on port 4000 on the Docker host.
If LiteLLM runs as a Docker service on the same network, use its service name instead:
LITELLM_BASE_URL=http://litellm:4000
You can override the value before starting Compose.
Linux/macOS shell:
export LITELLM_BASE_URL=http://litellm:4000
docker compose -f docker-compose.security.yml up -d --build
PowerShell:
$env:LITELLM_BASE_URL = "http://litellm:4000"
docker compose -f docker-compose.security.yml up -d --build
Connect Open WebUI
Configure an OpenAI-compatible connection in Open WebUI and point it to the security gateway instead of directly to LiteLLM.
Open WebUI in another Docker stack on the same host
Use:
http://host.docker.internal:8080/v1
Open WebUI on the same Docker network
Use:
http://security-gateway:8080/v1
Use the same LiteLLM API/virtual key you normally use. The gateway forwards the Authorization header to LiteLLM.
[!WARNING]
Remove or disable the old direct Open WebUI -> LiteLLM connection. If users can still reach LiteLLM directly, they can bypass the security gateway.

Test model discovery
If LiteLLM requires a key:
curl http://127.0.0.1:8080/v1/models \
  -H "Authorization: Bearer YOUR_LITELLM_KEY"
PowerShell:
$headers = @{
    Authorization = "Bearer YOUR_LITELLM_KEY"
}

Invoke-RestMethod \
    -Headers $headers \
    http://127.0.0.1:8080/v1/models
Test a normal request
curl http://127.0.0.1:8080/v1/chat/completions \
  -H "Authorization: Bearer YOUR_LITELLM_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "YOUR_LITELLM_MODEL",
    "messages": [
      {
        "role": "user",
        "content": "Write a short hello message."
      }
    ]
  }'
If the request passes policy checks, it is forwarded to LiteLLM normally.
Test a blocked request
Example using a protected internal term:
curl http://127.0.0.1:8080/v1/chat/completions \
  -H "Authorization: Bearer YOUR_LITELLM_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "YOUR_LITELLM_MODEL",
    "messages": [
      {
        "role": "user",
        "content": "Please summarize PROJECT-AURORA financial details."
      }
    ]
  }'
A blocked request returns HTTP 403 with a response similar to:
{
  "error": {
    "message": "Request blocked by the information security policy.",
    "type": "security_policy_block",
    "categories": [
      "TRADE_SECRET"
    ],
    "request_id": "..."
  }
}
Sensitive matched values are intentionally not returned in the error body.
Direct scanning API
Scan text
curl -X POST http://127.0.0.1:8080/v1/scan/text \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Contact user@example.org",
    "source": "manual-test"
  }'
Example result:
{
  "request_id": "...",
  "action": "BLOCK",
  "categories": ["PII"],
  "findings": [
    {
      "category": "PII",
      "detector": "PRESIDIO:EMAIL",
      "score": 0.85,
      "count": 1
    }
  ],
  "content_sha256": "..."
}
Scan a file
curl -X POST http://127.0.0.1:8080/v1/scan/file \
  -F "file=@./document.pdf"
The file is malware-scanned, MIME-detected, text-extracted, and then passed through the same local security checks.
Configuration
Environment variables used by the gateway:
Variable	Default	Description
LITELLM_BASE_URL	http://host.docker.internal:4000	LiteLLM upstream base URL
UPSTREAM_TIMEOUT	600	Upstream timeout in seconds
TIKA_URL	http://tika:9998	Apache Tika service URL
CLAMAV_HOST	clamav	ClamAV host
CLAMAV_PORT	3310	ClamAV daemon port
FAIL_CLOSED	true	Block requests when critical security checks fail
MAX_TEXT_CHARS	500000	Maximum text size accepted for inspection
MAX_FILE_BYTES	26214400	Maximum uploaded file size, 25 MiB by default
POLICY_FILE	/app/policy.yaml	Security policy path
LOG_LEVEL	INFO	Application log level


Policy configuration
Most organization-specific behavior is configured in:
security-gateway/policy.yaml
Important settings include:
block_categories:
  - PII
  - SECRET
  - TRADE_SECRET
  - PROMPT_INJECTION
  - MALWARE
  - UNSUPPORTED_FILE
  - SECURITY_SERVICE_UNAVAILABLE

block_person_names: false
pii_score_threshold: 0.80
block_person_names is disabled by default because person-name NER can create significant false positives. Enable it only if that behavior matches your policy and test data.
Privacy and logging
The application is designed not to log raw prompts or matched secret values in normal security events.
Security logs contain metadata such as:
- request ID;
- action (ALLOW / BLOCK);
- SHA-256 hash;
- detected categories.
You should still review logging across the entire stack, including:
- reverse proxies;
- Open WebUI;
- LiteLLM;
- observability/APM systems;
- container logs;
- SIEM collectors.
A DLP gateway does not help if the same sensitive prompt is stored unredacted somewhere else in the request path.
Security model
The intended trust boundary is:
Untrusted / user-controlled
        |
        v
Security Gateway
        |
        | inspected traffic only
        v
Trusted LLM proxy / provider path
For the gateway to be effective:
1. clients must not be able to bypass it and connect directly to LiteLLM;
2. LiteLLM should be reachable only from trusted network segments or the gateway;
3. Tika and ClamAV should not be exposed publicly;
4. service-to-service authentication should be added for production deployments;
5. the gateway itself should be protected by network controls, TLS, rate limits, and authentication appropriate to your environment.
Current limitations
This project intentionally documents its current limits.
No model-output DLP yet
The current OpenAI-compatible proxy scans requests before forwarding them upstream. It does not yet inspect or redact model responses before returning them to the client.
Raw Open WebUI uploads are not automatically quarantined
The /v1/scan/file endpoint can inspect files, but the gateway does not automatically intercept Open WebUI's native binary upload endpoint.
For strict pre-indexing quarantine, integrate the file-upload path so that raw files are sent to /v1/scan/file before storage or RAG indexing.
Prompt-injection detection is rule-based
Current prompt-injection detection uses heuristics and regex rules. It should be complemented by a local multilingual classifier and application-level tool authorization for higher-risk deployments.
Commercial-secret detection is policy/rule based
The gateway does not magically know what your organization considers a trade secret. Detection quality depends on your policy, dictionaries, labels, protected terms, and future semantic classifiers.
Limited OpenAI-compatible surface
The transparent proxy currently implements only:
- /v1/models
- /v1/chat/completions
- /v1/responses
Other OpenAI-compatible endpoints are not automatically proxied.
Detection is probabilistic
No automated DLP or security classifier can guarantee detection of all sensitive data, secrets, or adversarial prompts. Use layered controls.
Production hardening checklist
Before using the project in a production environment, consider:
- pinning Docker images and Python dependencies to reviewed versions/digests;
- using TLS or mTLS between services;
- placing LiteLLM behind the gateway on a private network;
- adding authentication to the gateway itself;
- adding per-user/service rate limits;
- adding YARA or additional file-security rules;
- adding a local multilingual prompt-injection classifier;
- adding a local semantic classifier for confidential/trade-secret content;
- implementing model-output DLP;
- implementing raw-upload quarantine before RAG ingestion;
- adding archive recursion/zip-bomb controls if archives are enabled;
- adding regression tests based on your real data-classification policy;
- testing bypasses, encoding tricks, Unicode normalization, and adversarial inputs;
- monitoring false positives and false negatives;
- verifying that no logs or traces persist raw sensitive content.
Optional Open WebUI filter
openwebui_filter.py is included as an additional UI-level integration layer.
It can provide earlier blocking and friendlier user-visible status messages, but it should not replace the network gateway as the primary enforcement point.
Recommended design:
Open WebUI Filter         -> UX / early feedback
Security Gateway          -> mandatory enforcement boundary
LiteLLM                   -> model routing / provider abstraction
Components
The project integrates several self-hosted/open-source components:
- FastAPI — gateway API;
- Presidio Analyzer — PII recognizers;
- Natasha — optional Russian NER;
- Gitleaks — secret detection;
- Apache Tika — file type detection and text extraction;
- ClamAV — malware scanning;
- LiteLLM — upstream OpenAI-compatible model proxy.
Review each dependency's license and security posture for your own distribution and compliance requirements.
Roadmap ideas
Potential next steps:
- model-response scanning and redaction;
- multilingual ML-based prompt-injection detection;
- semantic confidential-data classification;
- configurable per-user/per-group policies;
- audit-event export to SIEM;
- Prometheus metrics;
- OpenTelemetry integration;
- YARA rules;
- file quarantine workflow;
- image/OCR inspection;
- archive inspection with safe recursion limits;
- policy test suite and sample attack corpus;
- Kubernetes/Helm deployment examples.
Contributing
Issues and pull requests are welcome.
For security-sensitive changes, please include:
- the threat or bypass being addressed;
- a minimal reproduction case;
- tests covering both malicious and benign inputs;
- any expected false-positive impact.
Please do not include real credentials, personal data, or confidential company information in issues or test fixtures.
Responsible use
This project is intended to reduce accidental disclosure and improve LLM application security. It should be deployed as part of a broader security program, not treated as a single complete control.
Before public release, add an explicit repository LICENSE file matching the license you want to use for this project itself.
