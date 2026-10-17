from __future__ import annotations
import json
import os
import sys
import time

# Ensure risk-scorer root is in path
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from scorer.engine import DependencyRiskEngine
from scorer.models import InstallScripts, PackageQuery


def run_evaluation():
    corpus_path = os.path.join(current_dir, "corpus.json")
    with open(corpus_path, "r", encoding="utf-8") as f:
        corpus = json.load(f)

    engine = DependencyRiskEngine()

    tp = 0  # Actual malicious, predicted malicious
    fp = 0  # Actual clean, predicted malicious
    tn = 0  # Actual clean, predicted clean
    fn = 0  # Actual malicious, predicted clean

    results = []
    start_time = time.time()

    print("=================================================================")
    print("  AEGISCHAIN DEPENDENCY RISK SCORER EMPIRICAL EVALUATION")
    print("=================================================================")
    print(f"Total Labeled Corpus Samples: {len(corpus)}\n")
    print(f"{'Package':<28} {'Ecosystem':<10} {'Expected':<10} {'Score':<6} {'Predicted':<10} {'Result'}")
    print("-" * 75)

    for item in corpus:
        scripts = None
        if "scripts" in item:
            scripts = InstallScripts(**item["scripts"])

        pkg = PackageQuery(
            name=item["name"],
            ecosystem=item.get("ecosystem", "npm"),
            version=item.get("version", "1.0.0"),
            scripts=scripts,
        )

        score_res = engine.score_package(pkg)
        predicted_malicious = (score_res.score >= 65 or score_res.is_malicious or score_res.hard_gate_triggered)
        actual_malicious = (item["label"] == "malicious")

        status_str = "CORRECT"
        if actual_malicious and predicted_malicious:
            tp += 1
        elif not actual_malicious and not predicted_malicious:
            tn += 1
        elif not actual_malicious and predicted_malicious:
            fp += 1
            status_str = "FALSE_POS"
        else:
            fn += 1
            status_str = "FALSE_NEG"

        pred_label = "MALICIOUS" if predicted_malicious else "CLEAN"
        exp_label = "MALICIOUS" if actual_malicious else "CLEAN"
        print(f"{item['name']:<28} {pkg.ecosystem:<10} {exp_label:<10} {score_res.score:<6} {pred_label:<10} [{status_str}]")

        results.append({
            "package": item["name"],
            "ecosystem": pkg.ecosystem,
            "expected": item["label"],
            "predicted": pred_label.lower(),
            "score": score_res.score,
            "factors": [f.name for f in score_res.factors],
            "correct": (status_str == "CORRECT"),
        })

    elapsed = time.time() - start_time

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / len(corpus) if len(corpus) > 0 else 0.0

    print("-" * 75)
    print(f"True Positives:  {tp} (Correctly blocked attacks)")
    print(f"True Negatives:  {tn} (Correctly admitted clean packages)")
    print(f"False Positives: {fp} (Clean packages incorrectly flagged)")
    print(f"False Negatives: {fn} (Attacks that escaped detection)")
    print("-" * 75)
    print(f"Precision:       {precision:.4f} ({precision*100:.1f}%)")
    print(f"Recall:          {recall:.4f} ({recall*100:.1f}%)")
    print(f"F1-Score:        {f1:.4f}")
    print(f"Accuracy:        {accuracy:.4f} ({accuracy*100:.1f}%)")
    print(f"Evaluation Time: {elapsed:.2f}s")
    print("=================================================================")

    # Write empirical results to bench/results/risk-scorer-eval.json
    bench_dir = os.path.join(os.path.dirname(parent_dir), "bench", "results")
    os.makedirs(bench_dir, exist_ok=True)
    out_path = os.path.join(bench_dir, "risk-scorer-eval.json")

    eval_data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_samples": len(corpus),
        "true_positives": tp,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "evaluation_duration_seconds": round(elapsed, 4),
        "samples": results,
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(eval_data, f, indent=2)

    print(f"Results successfully saved to {out_path}")
    return eval_data


if __name__ == "__main__":
    run_evaluation()
