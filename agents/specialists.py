from agents.base_agent import BaseAgent
from tools.tool_registry import TOOL_REGISTRY


class ReconSpecialist(BaseAgent):
    def __init__(self, name: str = "recon_specialist", **kwargs):
        super().__init__(name, **kwargs)
        self.specialist_role = "recon"

    def _build_initial_prompt(self) -> tuple[str, str]:

        dynamic_tools = []
        for name, data in TOOL_REGISTRY.items():
            if data.get('category') in ('scanning', 'recon', 'web'):
                desc = data['description']
                # Try to load or learn dynamic syntax
                if hasattr(self, 'tools') and self.tools:
                    syntax = self.tools.learn_tool_syntax(name)
                    if syntax:
                        desc += f" {syntax}"
                dynamic_tools.append(f"- {name}: {desc}")

        stealth_enabled = False
        if hasattr(self, "session") and hasattr(self.session, "stealth_config"):
            stealth_enabled = any(self.session.stealth_config.values())

        if stealth_enabled:
            mandate = "Stealth is your highest priority. NEVER run aggressive scans (e.g., nmap -T4, aggressive ffuf)."
        else:
            mandate = "You are operating in UNRESTRICTED PERFORMANCE mode. Maximize scan speeds and concurrency (e.g., nmap -T4). Do NOT use rate-limiting."

        system_prompt = (
            "You are the GHOSTWIRE Recon Specialist. Your goal is to map the target's attack surface "
            "using ONLY non-intrusive discovery tools (Nmap, DNS lookups, whois, sslscan, whatweb, etc.). "
            "Do NOT try to exploit the target, generate payloads, or perform brute-forcing.\n\n"
            f"{mandate}\n"
            "When you are done or have gathered enough information, call 'return_result_to_manager' with your findings.\n\n"
            "--- AVAILABLE TOOLS & SYNTAX RULES ---\n"
            + "\n".join(dynamic_tools)
        )
        user_prompt = (
            f"Start reconnaissance on the target: {self.session.target}\n"
            f"Subtask to accomplish: {
                getattr(
                    self,
                    'subtask_context',
                    'General discovery')}"
        )
        return system_prompt, user_prompt

    async def run(self, subtask_context: str = None) -> dict:
        self.subtask_context = subtask_context or "General discovery"
        self.log.info(f"ReconSpecialist starting task: {self.subtask_context}")
        return self.run_react()


class ExploitSpecialist(BaseAgent):
    def __init__(self, name: str = "exploit_specialist", **kwargs):
        super().__init__(name, **kwargs)
        self.specialist_role = "exploit"

    def _build_initial_prompt(self) -> tuple[str, str]:
        dynamic_tools = []
        for name, data in TOOL_REGISTRY.items():
            if data.get('category') in (
                    'exploitation', 'post_exploitation', 'web'):
                desc = data['description']
                # Try to load or learn dynamic syntax
                if hasattr(self, 'tools') and self.tools:
                    syntax = self.tools.learn_tool_syntax(name)
                    if syntax:
                        desc += f" {syntax}"
                dynamic_tools.append(f"- {name}: {desc}")

        system_prompt = (
            "You are the GHOSTWIRE Exploit Specialist. Your goal is to gain initial access or confirm "
            "vulnerabilities using exploitation and delivery tools (sqlmap, hydra, custom python payloads, etc.). "
            "You must NOT perform broad port scans or generic domain searches.\n\n"
            "Adhere strictly to the rules of engagement. "
            "When you have achieved the objective or exhausted your options, call 'return_result_to_manager' with your results.\n\n"
            "--- AVAILABLE TOOLS & SYNTAX RULES ---\n"
            + "\n".join(dynamic_tools)
        )
        user_prompt = (
            f"Target: {self.session.target}\n"
            f"Subtask to accomplish: {
                getattr(
                    self,
                    'subtask_context',
                    'Perform exploitation')}"
        )
        return system_prompt, user_prompt

    async def run(self, subtask_context: str = None) -> dict:
        self.subtask_context = subtask_context or "Perform exploitation"
        self.log.info(
            f"ExploitSpecialist starting task: {
                self.subtask_context}")
        return self.run_react()


class ResearchSpecialist(BaseAgent):
    def __init__(self, name: str = "research_specialist", **kwargs):
        super().__init__(name, **kwargs)
        self.specialist_role = "research"

    def _build_initial_prompt(self) -> tuple[str, str]:
        system_prompt = (
            "You are the GHOSTWIRE Research Specialist. Your goal is to gather information via web search "
            "or read and analyze files on the system to help other agents. "
            "You do NOT have access to offensive tools. You can only use web_search, read_file, curl (for reading pages), etc.\n\n"
            "When you have found the requested information, call 'return_result_to_manager' to return it."
        )
        user_prompt = (
            f"Objective: Gather research information.\n"
            f"Subtask to accomplish: {
                getattr(
                    self,
                    'subtask_context',
                    'Analyze documentation')}"
        )
        return system_prompt, user_prompt

    async def run(self, subtask_context: str = None) -> dict:
        self.subtask_context = subtask_context or "Analyze documentation"
        self.log.info(
            f"ResearchSpecialist starting task: {
                self.subtask_context}")
        return self.run_react()
