
from intelligence.reasoning_engine import ReasoningEngine
from intelligence.structured_analyzer import StructuredAnalyzer
from core.ai_backend import AIBackend
import sys
from pathlib import Path

# Add project root to sys.path
project_root = str(Path(__file__).parent.parent)
sys.path.append(project_root)


def test_ai_backend_model_id():
    print("Testing AIBackend.query with model_id...")
    ai = AIBackend()

    # We won't actually perform a remote call if possible, or we'll catch errors
    # The goal is to see if it CRASHES with "unexpected keyword argument"
    try:
        # Using a fake model_id to see if it propagates correctly to the provider methods
        # Even if it fails due to invalid model, it shouldn't crash with
        # TypeError
        response = ai.query(
            "Test system prompt",
            "Test user message",
            model_id="gpt-3.5-turbo")
        print(f"Response (might be error but not crash): {response[:100]}...")
    except TypeError as e:
        print(f"FAILED: TypeError detected: {e}")
        return False
    except Exception as e:
        print(
            f"Caught expected exception (remote call failed as expected): {e}")

    print("AIBackend.query model_id propagation test passed (no TypeError).")
    return True


def test_structured_analyzer_propagation():
    print("\nTesting StructuredAnalyzer model_id propagation...")

    class MockAI:
        def __init__(self):
            self.last_model_id = None

        def query(self, system_prompt, user_message,
                  max_retries=4, model_id=None):
            self.last_model_id = model_id
            return '{"findings": []}'

    mock_ai = MockAI()
    analyzer = StructuredAnalyzer(ai_backend=mock_ai)

    analyzer.analyze_raw_output(
        "nmap",
        "nmap -sV target",
        "stdout",
        model_id="test-model")
    if mock_ai.last_model_id == "test-model":
        print("Success: analyze_raw_output propagated model_id.")
    else:
        print(
            f"FAILED: analyze_raw_output did not propagate model_id. Got: {
                mock_ai.last_model_id}")
        return False

    mock_ai.last_model_id = None
    analyzer.structure_recon_phase_output(
        [{"tool": "nmap", "stdout": "test"}], model_id="recon-model")
    if mock_ai.last_model_id == "recon-model":
        print("Success: structure_recon_phase_output propagated model_id.")
    else:
        print(
            f"FAILED: structure_recon_phase_output did not propagate model_id. Got: {
                mock_ai.last_model_id}")
        return False

    return True


def test_reasoning_engine_propagation():
    print("\nTesting ReasoningEngine model_id propagation...")

    class MockAI:
        def __init__(self):
            self.last_model_id = None

        def query(self, system_prompt, user_message,
                  max_retries=4, model_id=None):
            self.last_model_id = model_id
            return '{"reasoning_steps": []}'

    mock_ai = MockAI()
    engine = ReasoningEngine(ai_backend=mock_ai)

    engine.reason_about_findings({}, "target.com", model_id="reason-model")
    if mock_ai.last_model_id == "reason-model":
        print("Success: reason_about_findings propagated model_id.")
    else:
        print(
            f"FAILED: reason_about_findings did not propagate model_id. Got: {
                mock_ai.last_model_id}")
        return False

    mock_ai.last_model_id = None
    engine.prescribe_exploitation_actions(
        [], "target.com", model_id="prescribe-model")
    if mock_ai.last_model_id == "prescribe-model":
        print("Success: prescribe_exploitation_actions propagated model_id.")
    else:
        print(
            f"FAILED: prescribe_exploitation_actions did not propagate model_id. Got: {
                mock_ai.last_model_id}")
        return False

    return True


if __name__ == "__main__":
    success = True
    if not test_ai_backend_model_id():
        success = False
    if not test_structured_analyzer_propagation():
        success = False
    if not test_reasoning_engine_propagation():
        success = False

    if success:
        print("\nALL STABILIZATION TESTS PASSED!")
        sys.exit(0)
    else:
        print("\nSOME TESTS FAILED!")
        sys.exit(1)
