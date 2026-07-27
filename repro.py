from core.ai_backend import AIBackend
import sys


def test():
    print(f"Python path: {sys.path}")
    print("Initializing AIBackend...")
    try:
        detector = AIBackend()
        print("Calling detector.query(model_id='test')...")
        res = detector.query(
            "system prompt",
            "user message",
            max_retries=1,
            model_id="test")
        print(f"Result length: {len(res)}")
        import inspect
        print(f"AIBackend loaded from: {inspect.getfile(AIBackend)}")
        print(
            f"AIBackend.query signature: {
                inspect.signature(
                    AIBackend.query)}")
        print("SUCCESS")
    except TypeError as e:
        print(f"TypeError caught: {e}")
        import inspect
        print(f"AIBackend loaded from: {inspect.getfile(AIBackend)}")
        print(
            f"AIBackend.query signature: {
                inspect.signature(
                    AIBackend.query)}")
    except Exception as e:
        print(f"Other error: {e}")


if __name__ == "__main__":
    test()
