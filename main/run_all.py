import subprocess
import time
import os

# Simple helper to launch background processes
def launch(cmd, name):
    print(f"🚀 Starting {name}...")
    return subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

# Activate the venv
VENV_PY = os.path.join(os.getcwd(), "venv/bin/python3")

# Start AI modules
modules = [
    ("AI Domain Classifier", f"{VENV_PY} ai_modules/domain_classifier.py"),
]

# Start backend + dashboard
core = [
    ("API Handler", f"{VENV_PY} api_handler.py"),
    ("Dashboard", f"{VENV_PY} dashboard.py"),
]

# Optional real-time logs (comment out if you don’t want it)
# logs = [("Log Collector", f"{VENV_PY} log_collector.py")]
logs = []

# Launch all
procs = []
for name, cmd in modules + core + logs:
    p = launch(cmd, name)
    procs.append((name, p))
    time.sleep(2)

print("\n✅ All components started. Press Ctrl+C to stop.\n")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n🛑 Stopping all processes...")
    for name, p in procs:
        print(f"Terminating {name}...")
        p.terminate()
    print("All stopped.")
