import json
import re
from pathlib import Path
from typing import Dict, List
from utils.logger import get_logger

log = get_logger("syntax_learner")

# Universal placeholders. Stored syntax is kept ENGAGEMENT- and TARGET-agnostic
# so a pattern learned against one host/engagement can be safely re-used against
# the next one. We abstract on the way in and re-hydrate on the way out.
PH_TARGET = "<TARGET>"
PH_WORKDIR = "<WORKDIR>"

# A command is only worth remembering if it actually WORKED. These markers (any
# tool, no per-tool logic) mean the captured output is really a failure that was
# mis-scored as success upstream — never learn from it, or we poison generation
# (e.g. nmap's raw-socket "QUITTING!" once got stored as good syntax).
_HARD_FAIL_MARKERS = (
    "quitting", "operation not permitted", "permission denied",
    "requires root", "no such file", "command not found", "cannot find",
    "unrecognized", "invalid option", "no such option", "unknown flag",
    "flag provided but not defined", "usage:", "could not resolve",
    "name or service not known", "no targets were specified",
)

# Per-engagement absolute paths look like `…/eng_<hex>/…`. Abstract the whole
# prefix up to and including the engagement id so the remainder (sub-path +
# filename) is preserved but re-pointable at the current workspace.
_ENG_PATH_RE = re.compile(r'/[^\s"\']*?/eng_[0-9a-fA-F]{4,}')


class SyntaxLearner:
    """
    Persists PORTABLE command-syntax patterns across engagements.

    Helps the AI "heal" its command generation by remembering shapes that
    actually worked — but stored target-/path-agnostic so replaying a pattern
    in a new engagement never references a stale host or a file from a previous
    run (a major source of hallucinated `-l <file>` failures).
    """

    def __init__(self, memory_file_path: str = None):
        if not memory_file_path:
            # Default to intelligence/syntax_memory.json
            from config_paths import INTEL_DIR
            self.memory_file = Path(INTEL_DIR) / "syntax_memory.json"
        else:
            self.memory_file = Path(memory_file_path)

        self.memory: Dict[str, List[Dict[str, str]]] = self._load_memory()

    def _load_memory(self) -> Dict[str, List[Dict[str, str]]]:
        if not self.memory_file.exists():
            return {}
        try:
            with open(self.memory_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            log.error(
                f"Failed to load syntax memory from {
                    self.memory_file}: {e}")
            return {}

    def _save_memory(self):
        try:
            self.memory_file.parent.mkdir(parents=True, exist_ok=True)
            # Atomic write: dump to a temp file then replace, so an interrupted
            # (stall-killer / timeout) or concurrent write can't truncate/corrupt
            # the learned memory (same corruption class already fixed for waf_learner).
            _tmp = self.memory_file.with_name(self.memory_file.name + '.tmp')
            with open(_tmp, 'w', encoding='utf-8') as f:
                json.dump(self.memory, f, indent=2)
            _tmp.replace(self.memory_file)
        except Exception as e:
            log.error(
                f"Failed to save syntax memory to {
                    self.memory_file}: {e}")

    # ── Abstraction (universal, no per-tool logic) ────────────────────────────
    @staticmethod
    def _strip_workspace_wordlist(cmd: str) -> str:
        """The wordlist a fuzzer uses (-w/--wordlist) is a RUNTIME/ENVIRONMENT
        choice, NOT stable syntax. Memorizing a SPECIFIC path re-teaches a bad
        wordlist: a discovered-hosts file (recon_hosts.txt), or a standard list
        like /usr/share/dirb/wordlists/common.txt that ISN'T installed on this
        box — both fail every time the learned hint is reused. Abstract ANY
        wordlist value to the {WORDLIST} token, which the execution layer resolves
        to a real list (AI-provisioned → installed → written fallback). Generic
        across any tool that takes -w; heals already-poisoned memory on reuse via
        _rehydrate. Leaves an existing {WORDLIST} token untouched."""
        return re.sub(
            r'(-w|--wordlist)([= ]+)(?!\{WORDLIST\})\S+',
            r'\1\2{WORDLIST}', cmd or "")

    def _abstract(self, command: str, context: dict | None) -> str:
        """Strip the engagement/target identity out of a command so the stored
        pattern is reusable. Order matters: paths first, then the bare target."""
        out = command
        # 1. Per-engagement absolute paths → <WORKDIR>/<rest>
        out = _ENG_PATH_RE.sub(PH_WORKDIR, out)
        if context:
            workdir = (context.get("workdir") or "").rstrip("/")
            if workdir:
                out = out.replace(workdir, PH_WORKDIR)
            # 2. The concrete target host/IP → <TARGET> (scheme-insensitive).
            target = (context.get("target") or "").strip()
            host = re.sub(r'^[a-z]+://', '', target).split("/")[0].split(":")[0]
            for tok in {target, host}:
                if tok and len(tok) > 3:
                    out = re.sub(rf'(?<![\w.]){re.escape(tok)}(?![\w])',
                                 PH_TARGET, out)
        # 3. A workspace file passed as a -w wordlist is not reusable syntax.
        out = self._strip_workspace_wordlist(out)
        return out

    def _rehydrate(self, command: str, context: dict | None) -> str:
        """Re-point an abstracted pattern at the CURRENT engagement/target."""
        # Heal any already-stored poisoned entry (workspace file as -w wordlist)
        # before re-pointing paths, so old memory can't re-suggest a bad list.
        out = self._strip_workspace_wordlist(command)
        if context:
            workdir = (context.get("workdir") or "").rstrip("/")
            if workdir:
                out = out.replace(PH_WORKDIR, workdir)
            target = (context.get("target") or "").strip()
            host = re.sub(r'^[a-z]+://', '', target).split("/")[0].split(":")[0]
            out = out.replace(PH_TARGET, host or target)
        return out

    @staticmethod
    def _looks_like_failure(text: str) -> bool:
        t = (text or "").lower()
        return any(m in t for m in _HARD_FAIL_MARKERS)

    def learn_syntax(self, tool_name: str, successful_command: str,
                     error_context: str = "", context: dict | None = None) -> None:
        """
        Record a working command SHAPE for a tool. The command is abstracted
        (target/paths placeholdered) before storage, and refused outright if its
        captured output actually indicates a failure.
        """
        # Defence-in-depth: even when the caller scored this a success, a
        # failure signature in the captured output means it was mis-scored.
        if self._looks_like_failure(error_context):
            log.debug(
                f"[SYNTAX LEARNER] Refusing to learn '{tool_name}': output "
                f"shows a hard-failure marker, not a real success.")
            return

        abstracted = self._abstract(successful_command, context).strip()
        if not abstracted:
            return

        if tool_name not in self.memory:
            self.memory[tool_name] = []

        # Avoid duplicates on the ABSTRACTED form (host-agnostic dedup).
        for entry in self.memory[tool_name]:
            if entry.get("syntax") == abstracted:
                return

        self.memory[tool_name].append({
            "syntax": abstracted,
            "error_context_resolved": error_context[:200] if error_context else "General syntax repair"
        })

        if len(self.memory[tool_name]) > 10:
            self.memory[tool_name] = self.memory[tool_name][-10:]

        self._save_memory()
        log.info(
            f"[SYNTAX LEARNER] Learned portable syntax for '{tool_name}': {abstracted[:80]}")

    def get_syntax_hints(self, tools_list: List[str] = None,
                         context: dict | None = None) -> str:
        """
        Return known-working command SHAPES for the requested tools, re-pointed
        at the current engagement/target. Presented as adaptable references —
        never "copy verbatim" — and the AI is reminded to verify inputs exist.
        """
        hints = []
        if not self.memory:
            return ""

        tools_to_check = tools_list if tools_list else list(self.memory.keys())

        for tool in tools_to_check:
            if tool in self.memory and self.memory[tool]:
                hints.append(f"Tool '{tool}' patterns that worked before:")
                for entry in self.memory[tool]:
                    shape = self._rehydrate(entry['syntax'], context)
                    hints.append(f"  - `{shape}`")

        if hints:
            return (
                "\n### LEARNED SYNTAX MEMORY (reference patterns — adapt the "
                "target and paths to the CURRENT task; only pass an input file "
                "if it actually exists in the workspace right now)\n"
                + "\n".join(hints) + "\n")
        return ""
