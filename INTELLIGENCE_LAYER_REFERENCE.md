# Intelligence Layer - Quick Reference Guide

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Exploitation Phase                       │
└──────────────────┬──────────────────────────────────────────┘
                   │
        ┌──────────▼──────────┐
        │  All Findings from  │
        │  Recon Phase        │
        └──────────┬──────────┘
                   │
        ┌──────────▼──────────────────────────────────────┐
        │   Intelligence Layer (New)                      │
        └──────────┬──────────────────────────────────────┘
                   │
    ┌──────────────┼──────────────┬──────────────────────┐
    │              │              │                      │
    │              │              │                      │
    ▼              ▼              ▼                      ▼
┌─────────┐  ┌──────────┐  ┌──────────────┐  ┌──────────────┐
│ Finding │  │Evidence  │  │Constraint    │  │Tool Success  │
│ Scorer  │  │ Router   │  │ Engine       │  │ Tracker      │
└────┬────┘  └────┬─────┘  └──────┬───────┘  └──────┬───────┘
     │            │               │                 │
     │    CVE     │               │                 │
     │  Database  │               │                 │
     │            │               │                 │
     └────────────┴───────────────┴─────────────────┘
                      │
         ┌────────────▼─────────────┐
         │  Enhanced AI Context     │
         │  (Scored Findings +      │
         │   Routed Exploits +      │
         │   Constraints)           │
         └────────────┬─────────────┘
                      │
         ┌────────────▼─────────────┐
         │  AI Exploitation Engine  │
         │  (Improved)              │
         └────────────┬─────────────┘
                      │
         ┌────────────▼─────────────┐
         │  Tool Execution          │
         │  (Track Results)         │
         └─────────────────────────┘
```

---

## 📚 Module Reference

### 1. CVE_DATABASE (`cve_database.py`)

**Purpose**: Maps technologies to known exploitable vulnerabilities

**Key Functions**:
```python
find_cves_for_tech(tech_name: str, version: str) → list
  # Returns: [{"tech": "WordPress", "version": "5.8", "cves": ["CVE-2021-39200"]}]

get_exploit_types_for_tech(tech_name: str) → list
  # Returns: ["plugin_upload_rce", "options_exposure", "user_enumeration"]

get_discovery_patterns(tech_name: str) → list
  # Returns: [r"/wp-admin/", r"/wp-content/", r"/wp-includes/"]
```

**Example**:
```python
from intelligence.cve_database import find_cves_for_tech
cves = find_cves_for_tech("WordPress", "5.8.1")
# → [
#   {"tech": "WordPress", "version": "5.8", "cves": ["CVE-2021-39200", "CVE-2021-39201"]},
#   {"tech": "WordPress", "version": "all", "exploit_types": [...]}
# ]
```

**Data Structure**:
```python
CVE_MAPPINGS = {
    "wordpress": {
        "5.8": {"cves": [...], "severity": "high"},
        "generic": {"discovery_patterns": [...], "exploit_types": [...]}
    },
    "apache": {...},
    "php": {...},
    # ...etc
}
```

---

### 2. FINDING SCORER (`finding_scorer.py`)

**Purpose**: Rates findings by confidence, exploitability, and priority

**Key Classes**:
```python
FindingScorer
  - score_finding(finding: dict) → dict (with scores)
  - score_findings_batch(findings: list) → list (sorted by score)

NegativeEvidenceTracker
  - create_negative_finding(...) → dict
  - should_retry_exploitation(...) → bool
```

**Scoring Formula**:
```
overall_score = confidence × exploitability × priority
  confidence ∈ [0.5, 0.95]   # How certain are we?
  exploitability ∈ [0.4, 1.0] # How easy to exploit?
  priority ∈ [0.3, 0.95]      # How urgent?
  
high_value = overall_score > 0.70
```

**Example**:
```python
from intelligence.finding_scorer import FindingScorer

finding = {
    "type": "vulnerability",
    "detail": "WordPress 5.8.1 with CVE-2021-39200",
    "severity": "high",
    "source": "nuclei"
}

scored = FindingScorer.score_finding(finding)
# → {
#   "confidence": 0.95,
#   "exploitability": 0.85,
#   "priority": 0.95,
#   "overall_score": 0.76,
#   "is_high_value": True,
#   "should_exploit_immediately": True
# }
```

---

### 3. EVIDENCE ROUTER (`evidence_router.py`)

**Purpose**: Maps findings to exploitation strategies and tools

**Key Classes**:
```python
EvidenceRouter
  - route_finding(finding: dict) → dict
  - route_findings_batch(findings: list) → dict (grouped by severity)
  - get_recommended_commands(routed_findings: list) → list

TechStackRouter
  - route_tech_stack(tech_stack: list) → list
  - _generate_exploit_command(...) → dict
```

**Example**:
```python
from intelligence.evidence_router import EvidenceRouter

finding = {"type": "sql_injection", "detail": "Login parameter vulnerable"}
route = EvidenceRouter.route_finding(finding)
# → {
#   "matched_rule": "sqli",
#   "confidence": 0.9,
#   "tools": ["sqlmap", "curl", "dalfox"],
#   "approaches": [
#     "Initiate automated SQL injection testing...",
#     "Construct your command dynamically..."
#   ]
# }
```

**Routing Rules** (15+ finding types):
```
sqli → sqlmap
xss → dalfox
cors_misconfig → curl
env_exposure → curl
git_exposure → curl
lfi/rfi → curl
rce → commix
ssh → hydra
jwt → jwt-cli
# ... and many more
```

---

### 4. CONSTRAINT ENGINE (`constraint_engine.py`)

**Purpose**: Ensures AI exploits only vulnerabilities with evidence

**Key Classes**:
```python
ConstraintEngine
  - build_constraints_from_findings(...) → dict
  - validate_exploitation_command(...) → dict (allowed, reason, fix)
  - filter_tool_list(...) → list

ExploitationPlanner
  - plan_exploitation_stages(...) → list[dict]
```

**Example**:
```python
from intelligence.constraint_engine import ConstraintEngine

constraints = ConstraintEngine.build_constraints_from_findings(all_findings)
# → {
#   "can_attempt": {
#     "sql_injection": True,      # Evidence of SQLi found
#     "xss": False,               # No XSS evidence
#     "rce": False,               # No RCE evidence
#   },
#   "tested_and_failed": [("lfi", "Already tested, doesn't exist")],
#   "tool_priority": {"curl": 1.0, "sqlmap": 0.8, "nuclei": 0.4},
#   "blocked_tools": []
# }

# Validate a command
result = ConstraintEngine.validate_exploitation_command(
    "sqlmap -u target",
    constraints
)
# → {"allowed": True, "reason": "Command is allowed"}

result = ConstraintEngine.validate_exploitation_command(
    "dalfox url target",  # XSS without evidence
    constraints
)
# → {
#   "allowed": False,
#   "reason": "XSS exploit without evidence",
#   "suggested_fix": "First identify XSS vectors in parameters"
# }
```

**Multi-Stage Planning**:
```python
stages = ExploitationPlanner.plan_exploitation_stages(findings, constraints)
# → [
#   {
#     "stage": 1,
#     "name": "Deep Enumeration",
#     "commands": ["curl ...", "whatweb ..."]
#   },
#   {
#     "stage": 2,
#     "name": "Vulnerability Testing",
#     "commands": ["sqlmap ...", "dalfox ..."]
#   },
#   {
#     "stage": 3,
#     "name": "Exploitation",
#     "commands": ["...specific CVE exploit..."]
#   }
# ]
```

---

### 5. TOOL SUCCESS TRACKER (`tool_success_tracker.py`)

**Purpose**: Learns which tools work best on which target types

**Key Class**:
```python
ToolSuccessTracker
  - log_tool_result(tool, target_type, success, duration)
  - get_tool_effectiveness(tool, target_type) → dict
  - rank_tools_for_target(tools, target_type) → list
  - profile_target(target_url, tech_stack, waf_type) → dict
```

**Example**:
```python
from intelligence.tool_success_tracker import ToolSuccessTracker

tracker = ToolSuccessTracker()

# Log tool results
tracker.log_tool_result("sqlmap", "wordpress", success=True, duration=45)
tracker.log_tool_result("nuclei", "wordpress", success=False, duration=120)

# Get effectiveness
metrics = tracker.get_tool_effectiveness("sqlmap", "wordpress")
# → {
#   "success_rate": 0.80,
#   "total_runs": 5,
#   "avg_duration": 42.3,
#   "recommendation": "highly_effective"
# }

# Rank tools for target type
ranked = tracker.rank_tools_for_target(
    ["curl", "sqlmap", "nuclei"],
    "wordpress"
)
# → [
#   ("curl", {"success_rate": 1.0, ...}),
#   ("sqlmap", {"success_rate": 0.80, ...}),
#   ("nuclei", {"success_rate": 0.30, ...}),
# ]

# Persistence
tracker._save_metrics()  # Saved to tool_metrics.json
```

---

## 🔄 Integration in Exploitation Agent

### How It Works:

**Step 1: Initialize Intelligence Layer**
```python
if INTELLIGENCE_AVAILABLE:
    # Score findings
    scored_findings = FindingScorer.score_findings_batch(all_findings)
    
    # Route them
    routed = EvidenceRouter.route_findings_batch(scored_findings)
    
    # Build constraints
    constraints = ConstraintEngine.build_constraints_from_findings(all_findings)
    
    # Plan stages
    stages = ExploitationPlanner.plan_exploitation_stages(all_findings, constraints)
    
    # Initialize tracker
    tracker = ToolSuccessTracker()
```

**Step 2: Build AI Context**
```python
intelligence_guidance = """
### INTELLIGENCE LAYER GUIDANCE
  • wordpress_vuln: WordPress 5.8.1 with CVE-2021-39200
    Confidence: 95% | Exploitability: 85%
  • sql_injection: Login parameter vulnerable
    Confidence: 90% | Exploitability: 70%
"""

static_context += intelligence_guidance
```

**Step 3: AI Exploitation Loop**
```python
while commands_run < max_commands:
    # AI sees enhanced context with intelligence guidance
    command = ai.generate_next_command(static_context, cmd_history)
    
    # Validate command against constraints (NEW)
    if INTELLIGENCE_AVAILABLE:
        validation = ConstraintEngine.validate_exploitation_command(
            command, constraints
        )
        if not validation["allowed"]:
            # Skip this command, tell AI why
            continue
    
    # Execute command
    result = safe_run_tool(...)
    
    # Track success (NEW)
    if INTELLIGENCE_AVAILABLE:
        tracker.log_tool_result(tool_name, target_type, result.success)
    
    # Continue loop
    cmd_history.append({...})
```

---

## 🎯 Decision Flow Diagrams

### Finding Scoring:
```
Finding
  ↓
Is it in noise list? → Yes → Confidence = 0.5
  ↓ No
Is it from tool? → Yes → Confidence = 0.8
  ↓ No
Is it header? → Yes → Confidence = 0.95
  ↓ No
Default confidence = 0.65
  ↓
Rate exploitability based on type
  ↓
Rate priority based on severity
  ↓
Score = confidence × exploitability × priority
  ↓
Is score > 0.70? → Yes → HIGH VALUE, suggest exploit
  ↓ No
Low-value finding, deprioritize
```

### Command Validation:
```
AI generates command
  ↓
Is it a valid allowed tool? → No → Reject
  ↓ Yes
Extract exploit type from command
  ↓
Do we have evidence for this exploit? → No → Reject
  ↓ Yes
Did we already test this and fail? → Yes → Reject
  ↓ No
Is WAF active and tool is noisy? → Yes → Warn, maybe skip
  ↓ No
Allow command ✓
```

### Tool Ranking:
```
Get all tools for target
  ↓
For each tool:
  ├─ score = success_rate × 0.6
  ├─ + (1 - normalized_duration) × 0.3
  └─ + data_reliability × 0.1
  ↓
Sort by score descending
  ↓
Filter by WAF (remove heavy tools if WAF present)
  ↓
Return ranked list
```

---

## 📊 Example Output

### Without Intelligence Layer:
```
[INFO] Running adaptive AI exploitation engine...
[DEBUG] Found 45 findings
[INFO] AI generating command 1/20...
[INFO] Executing: nuclei -u target
[DEBUG] nuclei: connection timeout after 120s
[WARNING] Tool failed, retrying with repair...
[INFO] AI generating command 2/20...
[INFO] Executing: nikto -h target
[INFO] nikto complete
[INFO] AI generating command 3/20...
... (10 more random tools)
```

### With Intelligence Layer:
```
[INFO] Running adaptive AI exploitation engine...
[INFO] Intelligence Layer: Found 12 findings
[INFO] Intelligence Layer: Scored 12 findings
[INFO] Intelligence Layer: 4 high-value findings detected
[INFO] Intelligence Layer: Detected WordPress 5.8.1 → CVE-2021-39200 applicable
[INFO] Intelligence Layer: Created 3-stage exploitation plan
[INFO] Intelligence Layer: Tool ranking updated from 80+ previous engagements

[PROMPT] INTELLIGENCE LAYER GUIDANCE:
  • WordPress 5.8.1 plugin RCE [score: 0.76] Confidence: 95% Exploitability: 85%
  • Unauthenticated API exposure [score: 0.71] Confidence: 90% Exploitability: 70%

[INFO] AI generating command 1/20...
[INFO] Executing: curl -s target/wp-json/wp/v2/plugins/
[SUCCESS] Found: akismet, jetpack, elementor plugins

[INFO] AI generating command 2/20...
[INFO] Executing: curl -s target/wp-admin/ 
[SUCCESS] Found: WordPress login panel

[INFO] Intelligence Layer: Tracking tool success (curl: 2/2 on wordpress)
[INFO] AI generating command 3/20...
[INFO] Executing: sqlmap -u target --batch
[SUCCESS] Found: SQL injection in search parameter

[INFO] Exploitation complete with 3 confirmed vulnerabilities
```

---

## 🔧 Customization

### Add Custom CVE Mapping:
```python
# intelligence/cve_database.py
CVE_MAPPINGS["your_app"] = {
    "1.0": {"cves": ["CVE-2024-12345"], "severity": "critical"},
    "generic": {
        "discovery_patterns": [r"header_signature", r"/api/version"],
        "exploit_types": ["rce", "sqli"]
    }
}
```

### Add Custom Routing Rule:
```python
# intelligence/evidence_router.py
ROUTING_RULES["your_finding"] = {
    "confidence": 0.9,
    "tools": ["curl", "custom_tool"],
    "approaches": [
        "Approach 1: ...",
        "Approach 2: ..."
    ]
}
```

### Adjust Scoring Weights:
```python
# intelligence/finding_scorer.py
EXPLOITABILITY_SCORES = {
    "your_vuln_type": 0.95,  # Add/modify scores
    ...
}
```

---

## 🐛 Troubleshooting

### Intelligence layer not loading:
```python
# exploitation_agent.py line 15
if INTELLIGENCE_AVAILABLE:
    print("Intelligence layer loaded")
else:
    print("Intelligence layer not available - running in safe mode")
```

### No high-value findings detected:
- Check `find_scorer.py` scoring thresholds (default 0.70)
- Increase `EXPLOITABILITY_SCORES` for your vuln types
- Add your technologies to `cve_database.py`

### Tool ranking not improving:
- Check `tool_metrics.json` permissions
- Run more engagements (need 3+ samples per tool/target combo)
- Verify tools are logging results correctly

---

## 📞 Integration Points

The intelligence layer integrates with:

1. **state_store** - Reads findings, reads phase_data
2. **exploitation_agent.py** - Loads modules, uses in _ai_enhanced_exploitation()
3. **ai_backend** - Gets AI prompts with intelligence context
4. **safe_run_tool()** - Results logged to tracker
5. **constraint_engine** - Validates AI-generated commands

All integration is **non-invasive** and **fully backward compatible**.
