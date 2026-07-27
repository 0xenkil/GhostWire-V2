# AI-Driven Autonomous Intelligence System

## Architecture Overview

The system now uses **zero hardcoding** for offensive decisions. All tactics, tool selection, WAF evasion, and pivot strategies are **learned from previous engagements** and driven by AI reasoning.

### Three Layers of Intelligence

#### 1. **Strategic Advisor** (`intelligence/strategic_advisor.py`)
- **Purpose**: Persistent knowledge base that learns what works and what doesn't
- **Learns From**: Every tool execution, every finding, every WAF encounter
- **Remembers**:
  - Tool effectiveness per target/tech-stack (success rate, avg execution time)
  - Tech stack patterns (what tools work for WordPress vs. Java vs. Kubernetes)
  - WAF types and proven evasion tactics for each
  - Failed approaches (what NOT to retry)
  - Discovery order efficiency (fastest order to find vulnerabilities)

- **Makes Decisions**:
  - `advise_tool_selection()` - "What tool should I run next based on history?"
  - `advise_waf_evasion()` - "What evasion tactic worked last time against this WAF?"
  - `advise_discovery_order()` - "What discovery sequence is most efficient?"
  - `should_continue_trying()` - "Should I keep retrying this tool or pivot?"

- **Persistent Storage**: `state/strategic_knowledge.json` (survives across engagements)

#### 2. **Self-Awareness Module** (`intelligence/self_awareness_module.py`)
- **Purpose**: Tracks what the system is confident about vs. what it's guessing
- **Tracks**:
  - Known facts (high confidence findings)
  - Uncertain facts (medium confidence)
  - Contradictions (conflicting findings)
  - Knowledge gaps (what we still need to discover)
  - Tactical assumptions and their validation

- **Feeds into AI prompts** so AI doesn't make overconfident decisions

#### 3. **Reasoning Engine** (`intelligence/reasoning_engine.py`)
- **Purpose**: Structured AI reasoning about findings
- **Reasons about**:
  - Which findings are exploitable
  - What prerequisites are needed
  - Risk levels of different tactics
  - Probability of success
  - Knowledge gaps that need filling
  - False positive risks

---

## How AI Learns

### Every Tool Execution Teaches
```python
# When a tool runs, success/failure is recorded:
advisor.record_tool_outcome(
    tool="nuclei",
    target="wordpress.example.com",
    success=True,
    duration=45.2,
    phase="exploitation"
)
```

**Effect**: Next scan on a WordPress site will prefer nuclei (higher success rate).

### Every Finding Teaches
```python
# When a vulnerability is found, it's recorded with confidence:
advisor.record_finding(
    finding_type="sql_injection",
    target="wordpress.example.com",
    detail="/user-login.php?id=",
    severity="critical",
    confidence=0.95
)
```

**Effect**: AI learns that WordPress sites often have SQL injection in login endpoints.

### Every WAF Encounter Teaches
```python
# When a WAF is detected and tactics are used:
advisor.record_waf_detection(
    waf_type="Cloudflare",
    tactics=["header_mutation", "rate_limiting", "user_agent_rotation"]
)
```

**Effect**: Next Cloudflare target will use proven tactics instead of guessing.

---

## How AI Makes Decisions

### 1. Tool Selection (No Hardcoding)
Before running a tool, AI consults the knowledge base:

```python
recommendations = advisor.advise_tool_selection(
    phase="exploitation",
    target="target.com",
    tech_stack=["PHP 7.4", "Apache", "MySQL 5.7"],
    discovered={...recon findings...}
)
```

**AI Prompt Includes**:
- What tools have worked on similar stacks before
- Success rates from history
- Tools that failed on this tech stack (avoid)
- Optimal discovery order from experience
- Time budget (don't re-run long tools)

### 2. WAF Evasion (Learned, Not Hardcoded)
When WAF blocks a tool, AI consults what's worked:

```python
waf_advice = advisor.advise_waf_evasion(
    waf_type="Cloudflare",
    current_approach="basic_curl",
    failures_so_far=[...list of 429 errors...]
)
```

**AI Knows**:
- Cloudflare blocks rate-limited scanners → use slowdown tactics
- Cloudflare detects Nuclei fingerprints → rotate user-agent
- Previous successes: header_mutation had 70% success

### 3. Pivot Decisions (Intelligent, Not Reactive)
System queries advisor before abandoning a tool:

```python
should_continue, reason = advisor.should_continue_trying(
    tool="gobuster",
    target="target.com",
    attempts=4,
    failure_rate=0.75
)

# Returns: (False, "Failure rate 75% exceeds historical 30%")
# → AI pivots to a different tool instead of infinite retry
```

---

## Knowledge Persistence

### File Structure
```
state/
├── strategic_knowledge.json          # Main knowledge base
├── waf_learned_*.json               # Per-WAF learned tactics
└── waf_bypass/                      # WAF bypass strategies
```

### What Persists Across Scans
- ✅ Tool effectiveness scores (success/failure/avg_time)
- ✅ Tech stack patterns (what works for each stack)
- ✅ WAF types and proven evasion tactics
- ✅ Failed approaches (don't retry these)
- ✅ Discovery order efficiency
- ✅ Finding patterns (typical vulnerabilities per tech)

### Learning Rate
- **Fast feedback**: Tool outcomes learned immediately
- **Persistent**: Saved to disk after every engagement
- **Exponential improvement**: More scans = smarter decisions

---

## Example: WordPress Scan

### First Scan (No History)
```
[1] Recon: AI uses default tools (nmap, curl, whatweb)
[2] AI detects: WordPress + PHP 7.4
[3] Exploitation: AI has no history, uses generic tools
    → nuclei timeout (30+ min)
    → sqlmap misses the vuln
    → gobuster gets 403'd
[4] Learning: Records failures
    ✓ nmap: success (30s)
    ✗ nuclei: timeout
    ✗ sqlmap: no findings
    ✗ gobuster: 403 blocked
```

### Second WordPress Scan (One Week Later)
```
[1] AI starts with historical knowledge:
    "WordPress sites typically have:
    - WP-specific endpoints
    - Plugin vulns (successful 80% of time)
    - Weak admin passwords (hydra works 40% of time)
    - WAF on 60% of targets"

[2] Recon: AI prioritizes:
    1. Plugin enumeration (works 80%)
    2. Theme detection (works 90%)
    3. Nuclei → SKIPS (timeout in history)
    4. Hydra → Tries (low resource, 40% success)

[3] Exploitation: AI uses learned tactics
    → Nuclei replaced with wpscantool or custom script
    → sqlmap + WordPress-specific payloads
    → Plugin-focused exploitation

[4] Result: 3x faster, higher success rate
```

---

## Integration Points

### Agents
Every agent has access to the strategic advisor:
- `ReconAgent`: Uses advisor to choose discovery tools in optimal order
- `ExploitationAgent`: Uses advisor to select exploitation tools
- `PersistenceAgent`: Uses advisor to avoid failed persistence techniques
- `ReportingAgent`: Uses advisor's stats for post-engagement insights

### Safe Tool Execution
Every tool run records outcome:
```python
# In safe_run_tool():
if result.success:
    advisor.record_tool_outcome(tool, target, success=True, ...)
else:
    advisor.record_tool_outcome(tool, target, success=False, ...)
```

### Finding Recording
Every finding feeds the knowledge base:
```python
# In add_finding():
advisor.record_finding(
    finding_type=finding_type,
    target=target,
    detail=detail,
    severity=severity,
    confidence=0.9 if critical else 0.6
)
```

---

## Configuration & Usage

### Enable Full Learning
The system is **fully enabled by default**. No config needed.

### Access Knowledge Base
```python
from intelligence.strategic_advisor import StrategicAdvisor

advisor = StrategicAdvisor()

# View what we know
print(advisor.get_confidence_report())

# Output:
# Tool Effectiveness (based on history):
#   nuclei: 65% (13/20)
#   gobuster: 45% (9/20)
#   curl: 95% (19/20)
#
# Tech Stack Patterns Known:
#   wordpress: 3 tools work
#   python_django: 5 tools work
#
# WAF Types Encountered:
#   cloudflare: 7 known tactics
#   modSecurity: 3 known tactics
```

### View Full Knowledge
```python
import json
with open("state/strategic_knowledge.json") as f:
    kb = json.load(f)
    
print("WordPress findings:")
for finding_type, instances in kb.get("finding_patterns", {}).items():
    if "wordpress" in str(instances):
        print(f"  {finding_type}: {len(instances)} instances")
```

### Reset Knowledge (Start Fresh)
```python
from pathlib import Path
Path("state/strategic_knowledge.json").unlink(missing_ok=True)
```

---

## Future Enhancements (Already Architected)

- [ ] Multi-objective optimization (speed vs. accuracy)
- [ ] Causal reasoning (why did this tactic fail?)
- [ ] Temporal learning (recent scans weighted higher)
- [ ] Team learning (share knowledge across team instances)
- [ ] Adversarial learning (detect honeypots vs. real vulns)

---

## Summary

**Before**: Hardcoded tool selection, fixed WAF tactics, brute-force retries
**Now**: 
- ✅ AI remembers what worked on similar targets
- ✅ AI pivots away from failing approaches
- ✅ AI selects tools based on proven effectiveness
- ✅ AI chooses WAF tactics from learned successes
- ✅ Every engagement makes the next one smarter
- ✅ Zero hardcoded tactics—all learned

The system is now **genuinely autonomous, intelligent, and self-improving**.
