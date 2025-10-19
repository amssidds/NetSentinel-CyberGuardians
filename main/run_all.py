# run_all.py
import subprocess
import time
import os
import signal
import sys
import requests

BANNER = r"""
=========================================
 🛡️  NetSentinel Unified Startup Script
=========================================
"""

def here(*parts):
    """Return an absolute path relative to this file."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), *parts)

def start(cmd, name):
    print(f"[*] Launching {name} ...")
    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )

def tail(process, name):
    """Verify a process didn't exit immediately."""
    time.sleep(0.3)
    if process.poll() is not None:
        out = process.stdout.read() if process.stdout else ""
        print(f"[!] {name} exited early.\n{out}")
        sys.exit(1)

def wait_for_service(url, timeout=30):
    """Poll a service URL until it responds (or timeout)."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(url, timeout=3)
            if r.status_code < 500:
                print(f"[+] {url} is up")
                return True
        except requests.exceptions.RequestException:
            pass
        time.sleep(2)
    print(f"[!] Timeout waiting for {url}")
    return False

def main():
    print(BANNER)
    processes = []

    try:
        ai_dir = here("ai_modules")

        # 1️⃣ Domain Classifier (6001)
        p_dc = start(["python3", os.path.join(ai_dir, "domain_classifier.py")], "Domain Classifier (6001)")
        processes.append(("Domain Classifier", p_dc))
        print("   ⏳ Waiting for Domain Classifier service (port 6001) ...")
        wait_for_service("http://127.0.0.1:6001/health")
        tail(p_dc, "Domain Classifier")

        # 2️⃣ Anomaly Detector (6002)
        p_anom = start(["python3", os.path.join(ai_dir, "anomaly_detector.py")], "Anomaly Detector (6002)")
        processes.append(("Anomaly Detector", p_anom))
        tail(p_anom, "Anomaly Detector")

        # 3️⃣ WHOIS Analyzer (6003)
        p_whois = start(["python3", os.path.join(ai_dir, "whois_analyzer.py")], "WHOIS Analyzer (6003)")
        processes.append(("WHOIS Analyzer", p_whois))
        tail(p_whois, "WHOIS Analyzer")

        # 4️⃣ API Handler (5000)
        p_api = start(["python3", here("api_handler.py")], "API Handler (5000)")
        processes.append(("API Handler", p_api))
        tail(p_api, "API Handler")

        # 5️⃣ Dashboard (8080)
        p_dash = start(["python3", here("dashboard.py")], "Dashboard (8080)")
        processes.append(("Dashboard", p_dash))
        tail(p_dash, "Dashboard")

        print("\n✅ All services launched successfully!\n")
        print("🌐 Dashboard   : http://127.0.0.1:8080")
        print("📡 API Handler : http://127.0.0.1:5000")
        print("🧠 WHOIS (/check): http://127.0.0.1:6003")
        print("📊 Anomaly Detector (/check): http://127.0.0.1:6002\n")
        print("Press CTRL+C to stop everything.\n")

        # Keep-alive loop
        while True:
            time.sleep(1)
            for name, proc in processes:
                if proc.poll() is not None:
                    print(f"\n[!] {name} stopped unexpectedly. Stopping all ...")
                    raise KeyboardInterrupt

    except KeyboardInterrupt:
        print("\n[!] Terminating all services...")
        for name, proc in processes:
            try:
                if proc.poll() is None:
                    os.kill(proc.pid, signal.SIGTERM)
                    time.sleep(0.2)
            except Exception:
                pass
        print("[✓] All services terminated. Goodbye.")

if __name__ == "__main__":
    main()
