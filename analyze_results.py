import json
import glob

results_files = sorted(glob.glob('stress_test_results/*.json'), reverse=True)
if results_files:
    with open(results_files[0]) as f:
        results = json.load(f)
        print("=" * 80)
        print(f"Results file: {results_files[0]}")
        print("=" * 80)

        failed_scenarios = []
        for i, s in enumerate(results['scenarios']):
            status = s['overall_status'].upper()
            print(f"{i + 1:2d}. {s['scenario']:<50} [{status}]")
            if status == "FAIL":
                failed_scenarios.append((i + 1, s))
                for phase, data in s['phases'].items():
                    if data['status'] == 'fail':
                        print(f"    - {phase}: {data['error']}")

        print("\n" + "=" * 80)
        print(f"FAILED SCENARIOS SUMMARY ({len(failed_scenarios)} total)")
        print("=" * 80)
        for idx, s in failed_scenarios:
            print(f"\nScenario {idx}: {s['scenario']}")
            print(f"  Difficulty: {s['difficulty']}")
            print(f"  Target: {s['target']}")
            for phase, data in s['phases'].items():
                print(
                    f"  {
                        phase:15s} : {
                        data['status']:6s} | {
                        data.get(
                            'error',
                            'OK')}")
