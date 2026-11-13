import json
import unittest
from pathlib import Path

from evaluation.evaluate import (
    DEFAULT_SUITE_PATH,
    compare_reports,
    compute_classification_metrics,
    mcnemar_exact_pvalue,
    validate_and_normalize_case,
)


class EvaluationSuiteTests(unittest.TestCase):
    def test_benchmark_suite_schema_and_uniqueness(self):
        with Path(DEFAULT_SUITE_PATH).open("r", encoding="utf-8") as fh:
            suite = json.load(fh)

        for modality in ("email", "sms", "url"):
            cases = suite[modality]
            self.assertGreaterEqual(len(cases), 50)
            ids = set()
            labels = set()
            for item in cases:
                self.assertNotIn(item["id"], ids)
                ids.add(item["id"])
                self.assertIn(item["label"], (0, 1))
                labels.add(item["label"])
                validate_and_normalize_case(modality, item)
            self.assertEqual(labels, {0, 1})

    def test_compute_classification_metrics_values(self):
        y_true = [0, 0, 1, 1]
        y_prob = [0.1, 0.6, 0.8, 0.3]
        pred_scam = [0, 0, 1, 0]
        pred_alert = [0, 1, 1, 0]

        metrics = compute_classification_metrics(y_true, y_prob, pred_scam, pred_alert)
        self.assertEqual(metrics["strict_scam"]["tn"], 2)
        self.assertEqual(metrics["strict_scam"]["fp"], 0)
        self.assertEqual(metrics["strict_scam"]["fn"], 1)
        self.assertEqual(metrics["strict_scam"]["tp"], 1)
        self.assertEqual(metrics["any_alert"]["fp"], 1)
        self.assertAlmostEqual(metrics["any_alert"]["fpr"], 0.5, places=4)
        self.assertAlmostEqual(metrics["any_alert"]["recall"], 0.5, places=4)

    def test_compare_reports_and_mcnemar_counts(self):
        def _report(fp_flag: int, fn_flag: int):
            return {
                "suite_b": {
                    m: {
                        "hard_benign": {"any_alert_fpr": float(fp_flag), "scam_fpr": 0.0},
                        "overall": {
                            "any_alert": {"recall": float(1 - fn_flag), "f1": 0.75},
                            "ranking_and_calibration": {"roc_auc": 0.9, "brier_score": 0.2},
                        },
                        "per_case": [
                            {"id": "c1", "label": 0, "pred_alert": fp_flag},
                            {"id": "c2", "label": 1, "pred_alert": 1 - fn_flag},
                        ],
                    }
                    for m in ("email", "sms", "url")
                }
            }

        comp = compare_reports(_report(1, 0), _report(0, 0))
        self.assertEqual(comp["email"]["hard_benign_alert_fpr_delta"], -1.0)
        self.assertEqual(comp["email"]["mcnemar_alert"]["current_only_correct"], 1)
        self.assertEqual(comp["email"]["mcnemar_alert"]["baseline_only_correct"], 0)
        self.assertEqual(mcnemar_exact_pvalue(0, 0), 1.0)


if __name__ == "__main__":
    unittest.main()

