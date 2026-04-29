"""Simple load test runner (requests-based) for quick smoke load.
This is a minimal script (not full locust) to generate concurrent requests.
"""
import argparse
import concurrent.futures
import requests
import time


def worker(target, n, pause):
    url = f"{target.rstrip('/')}/v1/validate"
    payload = {
        "llm_output": "Test load CVE-2024-0001. CVSS 7.5.",
        "context": {"alert_id": "load-test", "policy_profile": "default"},
    }
    for i in range(n):
        try:
            r = requests.post(url, json=payload, timeout=5)
            print(r.status_code, end=' ')
        except Exception as e:
            print('ERR', e, end=' ')
        time.sleep(pause)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--target', required=True)
    p.add_argument('--workers', type=int, default=5)
    p.add_argument('--iterations', type=int, default=20)
    p.add_argument('--pause', type=float, default=0.5)
    args = p.parse_args()

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = [ex.submit(worker, args.target, args.iterations, args.pause) for _ in range(args.workers)]
        concurrent.futures.wait(futures)


if __name__ == '__main__':
    main()
