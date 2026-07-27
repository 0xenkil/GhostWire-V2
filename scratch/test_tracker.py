from intelligence.tool_success_tracker import ToolSuccessTracker
from pathlib import Path


def test():
    tracker = ToolSuccessTracker(db_path=Path("scratch/test_metrics.json"))
    print("Testing log_tool_result with keyword arguments (as BaseAgent does)...")
    try:
        tracker.log_tool_result(
            tool_name="test_tool",
            success=False,
            target_type="wordpress",
            target="https://example.com",
            error_type="TIMEOUT"
        )
        print("Success! No TypeError.")
    except TypeError as e:
        print(f"Failed! TypeError: {e}")
    except Exception as e:
        print(f"Failed with unexpected error: {e}")


if __name__ == "__main__":
    test()
