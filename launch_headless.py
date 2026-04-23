#!/usr/bin/env python3
import sys
import os

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.session import EngagementSession
from core.orchestrator import Orchestrator
from utils.display import info, section, success

def main():
    target = "algo-matrix.space"
    mode = "redteam"
    ai_choice = None # AIBackend will auto-detect from .env
    
    section("HEADLESS RELAUNCH")
    info(f"Target: {target}")
    info(f"Mode: {mode}")
    info(f"AI: {ai_choice}")
    info("Status: Launching without interactive prompts...")

    session = EngagementSession(
        mode=mode,
        target=target,
        scope=[target],
        rules_of_engagement={
            "allow_exploitation": True,
            "allow_brute_force": False, 
            "allow_phishing": False,
            "allow_destructive": False
        },
        operator="Antigravity_Headless",
        ai_backend=ai_choice
    )

    info(f"Engagement ID: {session.engagement_id}")
    info(f"Results directory: {session.results_dir}")

    orchestrator = Orchestrator(session)
    
    try:
        orchestrator.run()
        success("Headless engagement completed successfully.")
    except Exception:
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
