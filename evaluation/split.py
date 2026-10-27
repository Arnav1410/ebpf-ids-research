"""Dataset-bound, local grouped holdouts using only the Python standard library."""
import math
import random


def _policy():
    return {
        "name": "seeded_greedy_exact_feature_groups_v1",
        "group_key": "complete six-integer feature vector",
        "allocation": (
            "Seed test support with the smallest normalized mixed-label group or "
            "one smallest pure group per class; break ties with a seeded shuffle. "
            "Consider groups in descending normalized size, adding only when the "
            "sum of squared per-class test-fraction errors decreases. Make one "
            "further add/remove pass, retaining both classes in both partitions."
        ),
        "stratification": "approximate row-count stratification of numeric classes 0 and 1",
        "conflicting_labels": "retain all rows and keep the entire mixed-label feature group together",
        "row_order": "ascending original row indices; no deduplication",
        "limitations": [
            "Exact feature groups are not capture sessions or evidence of duplicated traffic.",
            "Capture dates, sessions, feature semantics and numeric label meanings are unverified.",
            "This local holdout does not reproduce the paper's dated train/test protocol.",
            "Indivisible groups can prevent the requested fraction; greedy allocation is not an optimal subset search.",
        ],
    }


def _parameters(seed, test_fraction):
    if type(seed) is not int:
        raise ValueError("Split seed must be an integer, not a boolean")
    if (type(test_fraction) not in (int, float) or not 0 < test_fraction < 1
            or not math.isfinite(test_fraction)):
        raise ValueError("Requested test fraction must be finite and strictly between 0 and 1")


def _groups(dataset):
    if not dataset.features or len(dataset.features) != len(dataset.labels):
        raise ValueError("Split requires nonempty, aligned feature rows and labels")
    groups = {}
    for index, (features, label) in enumerate(zip(dataset.features, dataset.labels)):
        if type(label) is not int or label not in (0, 1):
            raise ValueError("Split requires numeric integer labels 0 and 1")
        if features not in groups:
            groups[features] = {"indices": [], "counts": [0, 0]}
        group = groups[features]
        group["indices"].append(index)
        group["counts"][label] += 1
    groups = list(groups.values())
    totals = [dataset.labels.count(label) for label in (0, 1)]
    if not all(totals):
        raise ValueError("Both numeric classes 0 and 1 are required for a supported holdout")
    for label in (0, 1):
        if sum(group["counts"][label] > 0 for group in groups) < 2:
            raise ValueError(
                f"Class {label} needs at least two distinct feature groups to occur "
                "in both train and test without group leakage"
            )
    return groups, totals


def _summary(dataset, groups, train_indices, test_indices):
    test_rows = set(test_indices)
    class_counts = {"all": {"0": 0, "1": 0},
                    "train": {"0": 0, "1": 0}, "test": {"0": 0, "1": 0}}
    group_counts = {
        "all": len(groups), "train": 0, "test": 0,
        "conflicting_label_groups": {"all": 0, "train": 0, "test": 0},
        "class_support": {part: {"0": 0, "1": 0} for part in ("all", "train", "test")},
    }
    for group in groups:
        part = "test" if group["indices"][0] in test_rows else "train"
        group_counts[part] += 1
        for label in (0, 1):
            key = str(label)
            count = group["counts"][label]
            class_counts["all"][key] += count
            class_counts[part][key] += count
            group_counts["class_support"]["all"][key] += int(count > 0)
            group_counts["class_support"][part][key] += int(count > 0)
        if all(group["counts"]):
            group_counts["conflicting_label_groups"]["all"] += 1
            group_counts["conflicting_label_groups"][part] += 1
    rows = len(dataset.features)
    return {
        "class_counts": class_counts,
        "group_counts": group_counts,
        "row_counts": {"all": rows, "train": len(train_indices), "test": len(test_indices)},
        "actual_test_fraction": len(test_indices) / rows,
        "actual_train_fraction": len(train_indices) / rows,
        "class_test_fractions": {
            label: class_counts["test"][label] / class_counts["all"][label]
            for label in ("0", "1")
        },
    }


def create_split(dataset, seed=2026, test_fraction=0.2):
    """Allocate whole feature groups, retaining every original row and both classes.

    The bounded greedy search targets row counts rather than counts of groups.
    It intentionally makes no fixed fraction-error guarantee for indivisible groups.
    """
    _parameters(seed, test_fraction)
    groups, totals = _groups(dataset)
    order = list(range(len(groups)))
    random.Random(seed).shuffle(order)

    def size(index):
        counts = groups[index]["counts"]
        return sum(counts[label] / totals[label] for label in (0, 1))

    mixed = [index for index in order if all(groups[index]["counts"])]
    pure = [[index for index in order
             if groups[index]["counts"][label] and not groups[index]["counts"][1 - label]]
            for label in (0, 1)]
    candidates = []
    if mixed:
        candidates.append({min(mixed, key=size)})
    if all(pure):
        candidates.append({min(pure[0], key=size), min(pure[1], key=size)})
    # With >=2 supporting groups per class, at least one of these seeds exists,
    # and either seed leaves nonzero training support for each class.
    selected = min(candidates, key=lambda candidate: (sum(size(i) for i in candidate), len(candidate)))
    counts = [sum(groups[index]["counts"][label] for index in selected) for label in (0, 1)]

    def score(values):
        return sum((values[label] / totals[label] - test_fraction) ** 2 for label in (0, 1))

    order.sort(key=size, reverse=True)  # Stable sort retains seeded tie-breaking.

    def consider(index):
        nonlocal counts
        direction = -1 if index in selected else 1
        proposed = [counts[label] + direction * groups[index]["counts"][label] for label in (0, 1)]
        if (all(0 < proposed[label] < totals[label] for label in (0, 1))
                and score(proposed) < score(counts) - 1e-15):
            if direction == 1:
                selected.add(index)
            else:
                selected.remove(index)
            counts = proposed

    for index in order:
        if index not in selected:
            consider(index)
    for index in order:
        consider(index)

    test_rows = {row for index in selected for row in groups[index]["indices"]}
    train_indices = [index for index in range(len(dataset.features)) if index not in test_rows]
    test_indices = sorted(test_rows)
    return {
        "schema_version": 1,
        "claim": "local_grouped_holdout_not_paper_reproduction",
        "dataset_identity": dict(dataset.identity),
        "seed": seed,
        "policy": _policy(),
        "requested_test_fraction": test_fraction,
        "train_indices": train_indices,
        "test_indices": test_indices,
        **_summary(dataset, groups, train_indices, test_indices),
    }


def _same_json(actual, expected):
    """Do not let bool/int or int/float equality conceal corrupted count metadata."""
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return (actual.keys() == expected.keys()
                and all(_same_json(actual[key], value) for key, value in expected.items()))
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(_same_json(a, b) for a, b in zip(actual, expected))
    return actual == expected


def validate_split(dataset, split):
    """Validate a saved manifest and return its index order without reallocating rows."""
    if not isinstance(split, dict) or type(split.get("schema_version")) is not int or split["schema_version"] != 1:
        raise ValueError("Unsupported split manifest schema; expected schema_version 1")
    if not _same_json(split.get("dataset_identity"), dataset.identity):
        raise ValueError("Split dataset identity does not match the supplied data/label hashes")
    if split.get("claim") != "local_grouped_holdout_not_paper_reproduction":
        raise ValueError("Split claim must identify a local grouped holdout, not paper reproduction")
    if not _same_json(split.get("policy"), _policy()):
        raise ValueError("Unsupported or corrupted split policy")
    _parameters(split.get("seed"), split.get("requested_test_fraction"))
    groups, _ = _groups(dataset)
    partitions = []
    rows = len(dataset.features)
    for name in ("train_indices", "test_indices"):
        indices = split.get(name)
        if not isinstance(indices, (list, tuple)) or not indices:
            raise ValueError(f"{name} must be a nonempty sequence of integer row indices")
        if any(type(index) is not int or not 0 <= index < rows for index in indices):
            raise ValueError(f"{name} contains a non-integer or out-of-range row index")
        if len(set(indices)) != len(indices):
            raise ValueError(f"{name} contains duplicate row indices")
        partitions.append(tuple(indices))
    train_indices, test_indices = partitions
    train_set, test_set = set(train_indices), set(test_indices)
    if train_set & test_set:
        raise ValueError("Train and test indices must be disjoint")
    if len(train_set) + len(test_set) != rows:
        raise ValueError("Split indices must cover every dataset row exactly once")
    for group in groups:
        if len({index in test_set for index in group["indices"]}) != 1:
            raise ValueError("Identical feature-vector group leaks across train and test partitions")
    for name, indices in (("train", train_indices), ("test", test_indices)):
        if {dataset.labels[index] for index in indices} != {0, 1}:
            raise ValueError(f"Split {name} partition must contain both numeric classes 0 and 1")
    expected = _summary(dataset, groups, train_indices, test_indices)
    for key, value in expected.items():
        if not _same_json(split.get(key), value):
            raise ValueError(f"Split {key} does not match the saved row membership")
    return train_indices, test_indices
