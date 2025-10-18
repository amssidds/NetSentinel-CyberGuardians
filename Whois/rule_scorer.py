import yaml, os

def apply_rules(features: dict, rules_file="rules.yaml"):
    # find the real location of rules.yaml
    base_dir = os.path.dirname(__file__)
    rules_path = os.path.join(base_dir, "rules.yaml")

    with open(rules_path, "r") as f:
        config = yaml.safe_load(f)

    score = 0
    reasons = []
    for name, rule in config["rules"].items():
        try:
            if eval(rule["when"], {}, features):
                score += rule["points"]
                reasons.append(rule["reason"])
        except Exception:
            pass

    thresholds = config["thresholds"]
    if score < thresholds["medium"]:
        label = "low"
    elif score < thresholds["high"]:
        label = "medium"
    else:
        label = "high"

    return score, label, reasons
