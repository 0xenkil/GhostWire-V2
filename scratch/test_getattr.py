try:
    print(getattr(None, "remote", None))
except Exception as e:
    print(f"Error: {e}")
