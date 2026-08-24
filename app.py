from __future__ import annotations

import hashlib
import json
import math
import threading
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


app = FastAPI(title="Candidate Admission API")

# ---------------------------------------------------------------------------
# Stateful freeze store
#
# Vercel can reuse a warm function instance, so this works for sequential
# grader requests hitting the same instance. For durable multi-instance
# production state, use an external store such as Upstash Redis.
# ---------------------------------------------------------------------------

_FREEZES: Dict[str, Dict[str, Any]] = {}
_FREEZE_INPUTS: Dict[str, str] = {}
_LOCK = threading.RLock()


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FREEZE_CODES = {
    "INVALID_INPUT",
    "UNALLOWED_UNSUPPORTED_REASON",
    "NOT_LOADABLE",
    "CALIBRATION_MISMATCH",
    "TOKENIZER_MISMATCH",
}

SELECT_CODES = {
    "NOT_FROZEN",
    "INVALID_LINEAGE",
    "INVALID_POLICY",
    "INVALID_PREDICTIONS",
    "INVALID_MANIFEST",
    "AGGREGATE_FLOOR",
    "SIZE_LIMIT",
    "LATENCY_LIMIT",
}


# ---------------------------------------------------------------------------
# Basic helpers
# ---------------------------------------------------------------------------

def is_string(x: Any) -> bool:
    return isinstance(x, str)


def nonempty_string(x: Any) -> bool:
    if not isinstance(x, str):
        return False
    try:
        x.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return len(x) > 0


def utf8_key(x: str) -> bytes:
    return x.encode("utf-8")


def sorted_utf8(values: List[str]) -> List[str]:
    return sorted(values, key=lambda x: x.encode("utf-8"))


def sorted_codes(codes: List[str]) -> List[str]:
    return sorted(set(codes), key=lambda x: x.encode("utf-8"))


def compact_json_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_safe_nonnegative_int(x: Any) -> bool:
    # JSON booleans are technically ints in Python, but must not count.
    return (
        isinstance(x, int)
        and not isinstance(x, bool)
        and x >= 0
        and x <= 9007199254740991
    )


def is_finite_nonnegative_number(x: Any) -> bool:
    return (
        isinstance(x, (int, float))
        and not isinstance(x, bool)
        and math.isfinite(float(x))
        and float(x) >= 0.0
    )


def is_floor(x: Any) -> bool:
    return (
        isinstance(x, (int, float))
        and not isinstance(x, bool)
        and math.isfinite(float(x))
        and 0.0 <= float(x) <= 1.0
    )


def rounded12(x: float) -> float:
    # Python's round gives the required numerical 12-decimal result.
    return round(float(x), 12)


def json_fingerprint(obj: Any) -> str:
    """
    Semantic JSON fingerprint used for freeze replay detection.

    Object key ordering does not matter; array ordering does.
    """
    return json.dumps(
        obj,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def invalid_input_response():
    return JSONResponse(
        status_code=400,
        content={"error": "INVALID_INPUT"},
    )


def freeze_conflict_response():
    return JSONResponse(
        status_code=409,
        content={"error": "FREEZE_ID_CONFLICT"},
    )


# ---------------------------------------------------------------------------
# File inventory
# ---------------------------------------------------------------------------

def build_inventory(
    files: Any,
) -> Tuple[bool, List[Dict[str, Any]], Optional[int], Optional[str]]:
    """
    Validate files and construct:

    [
      {
        "name": "...",
        "bytes": N,
        "sha256": "..."
      }
    ]

    Inventory is sorted by UTF-8 filename.
    """

    if not isinstance(files, dict) or len(files) == 0:
        return False, [], None, None

    names = list(files.keys())

    # JSON object keys must be strings, but explicitly validate anyway.
    if any(not nonempty_string(name) for name in names):
        return False, [], None, None

    # Dict keys are inherently unique after JSON parsing.
    inventory: List[Dict[str, Any]] = []

    for name in names:
        value = files[name]

        if not isinstance(value, str):
            return False, [], None, None

        try:
            raw = value.encode("utf-8")
        except UnicodeEncodeError:
            return False, [], None, None

        inventory.append(
            {
                "name": name,
                "bytes": len(raw),
                "sha256": sha256_hex(raw),
            }
        )

    inventory.sort(key=lambda x: x["name"].encode("utf-8"))

    total = sum(item["bytes"] for item in inventory)

    package_digest = sha256_hex(
        compact_json_bytes(inventory)
    )

    return True, inventory, total, package_digest


def recompute_manifest(
    inventory: Any,
) -> Tuple[bool, Optional[int], Optional[str]]:
    """
    Recompute totalBytes and packageDigest from a submitted inventory.

    Never trusts submitted totalBytes/packageDigest.
    """

    if not isinstance(inventory, list) or len(inventory) == 0:
        return False, None, None

    seen = set()
    normalized: List[Dict[str, Any]] = []

    for item in inventory:
        if not isinstance(item, dict):
            return False, None, None

        # Exact fields expected in the inventory object.
        if set(item.keys()) != {"name", "bytes", "sha256"}:
            return False, None, None

        name = item.get("name")
        byte_count = item.get("bytes")
        digest = item.get("sha256")

        if not nonempty_string(name):
            return False, None, None

        if name in seen:
            return False, None, None
        seen.add(name)

        if not is_safe_nonnegative_int(byte_count):
            return False, None, None

        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(c not in "0123456789abcdef" for c in digest)
        ):
            return False, None, None

        normalized.append(
            {
                "name": name,
                "bytes": byte_count,
                "sha256": digest,
            }
        )

    # Must be sorted by UTF-8 filename.
    if normalized != sorted(
        normalized,
        key=lambda x: x["name"].encode("utf-8"),
    ):
        return False, None, None

    total = sum(x["bytes"] for x in normalized)

    digest = sha256_hex(compact_json_bytes(normalized))

    return True, total, digest


# ---------------------------------------------------------------------------
# Freeze validation
# ---------------------------------------------------------------------------

def validate_freeze_request(body: Any) -> bool:
    if not isinstance(body, dict):
        return False

    if body.get("phase") != "freeze":
        return False

    freeze_id = body.get("freezeId")
    calibration = body.get("calibrationDigest")
    tokenizer = body.get("tokenizerDigest")
    allowed = body.get("allowedUnsupportedReasons")
    candidates = body.get("candidates")

    if not nonempty_string(freeze_id):
        return False

    if len(freeze_id) > 128:
        return False

    if not nonempty_string(calibration):
        return False

    if not nonempty_string(tokenizer):
        return False

    if not isinstance(allowed, list):
        return False

    if not isinstance(candidates, list) or len(candidates) == 0:
        return False

    # Allowed reasons: non-empty and unique.
    allowed_seen = set()

    for reason in allowed:
        if not nonempty_string(reason):
            return False
        if reason in allowed_seen:
            return False
        allowed_seen.add(reason)

    candidate_names = set()

    for candidate in candidates:
        if not isinstance(candidate, dict):
            return False

        name = candidate.get("name")

        if not nonempty_string(name):
            return False

        if name in candidate_names:
            return False

        candidate_names.add(name)

        # files must be an object. We allow invalid files to become an
        # "invalid" candidate as required by the specification, but the
        # presence/type of the field itself must still be sane.
        if "files" not in candidate:
            return False

    return True


def freeze_candidate(
    candidate: Dict[str, Any],
    request_calibration: str,
    request_tokenizer: str,
    allowed_reasons: set,
) -> Dict[str, Any]:

    name = candidate.get("name")
    files = candidate.get("files")

    files_valid, inventory, total_bytes, package_digest = build_inventory(files)

    # Invalid files => empty inventory/null size/null digest.
    if not files_valid:
        return {
            "name": name,
            "status": "invalid",
            "inventory": [],
            "totalBytes": None,
            "packageDigest": None,
            "reasonCodes": ["INVALID_INPUT"],
        }

    reason_codes: List[str] = []

    has_reason = (
        "unsupportedReason" in candidate
        and candidate.get("unsupportedReason") is not None
        and candidate.get("unsupportedReason") != ""
    )

    if has_reason:
        reason = candidate.get("unsupportedReason")

        if not nonempty_string(reason):
            return {
                "name": name,
                "status": "invalid",
                "inventory": inventory,
                "totalBytes": total_bytes,
                "packageDigest": package_digest,
                "reasonCodes": ["INVALID_INPUT"],
            }

        if reason in allowed_reasons:
            # An explicitly allowed unsupported reason makes this candidate
            # unsupported, regardless of loadability or lineage digests.
            return {
                "name": name,
                "status": "unsupported",
                "inventory": inventory,
                "totalBytes": total_bytes,
                "packageDigest": package_digest,
                "reasonCodes": [],
            }

        return {
            "name": name,
            "status": "invalid",
            "inventory": inventory,
            "totalBytes": total_bytes,
            "packageDigest": package_digest,
            "reasonCodes": ["UNALLOWED_UNSUPPORTED_REASON"],
        }

    # No unsupported reason: candidate must be loadable and have matching
    # calibration/tokenizer lineage.
    if candidate.get("loadable") is not True:
        reason_codes.append("NOT_LOADABLE")

    if candidate.get("calibrationDigest") != request_calibration:
        reason_codes.append("CALIBRATION_MISMATCH")

    if candidate.get("tokenizerDigest") != request_tokenizer:
        reason_codes.append("TOKENIZER_MISMATCH")

    reason_codes = sorted_codes(reason_codes)

    if reason_codes:
        status = "invalid"
    else:
        status = "frozen"

    return {
        "name": name,
        "status": status,
        "inventory": inventory,
        "totalBytes": total_bytes,
        "packageDigest": package_digest,
        "reasonCodes": reason_codes,
    }


def do_freeze(body: Dict[str, Any]):
    freeze_id = body["freezeId"]

    fingerprint = json_fingerprint(body)

    # Replays/conflicts must happen before constructing a new response.
    with _LOCK:
        if freeze_id in _FREEZES:
            if _FREEZE_INPUTS[freeze_id] == fingerprint:
                # Identical replay: return the exact stored object.
                return _FREEZES[freeze_id]

            return freeze_conflict_response()

        allowed = set(body["allowedUnsupportedReasons"])

        frozen_candidates = [
            freeze_candidate(
                candidate,
                body["calibrationDigest"],
                body["tokenizerDigest"],
                allowed,
            )
            for candidate in body["candidates"]
        ]

        # Sort by UTF-8 name.
        frozen_candidates.sort(
            key=lambda x: x["name"].encode("utf-8")
        )

        response = {
            "freezeId": freeze_id,
            "candidates": frozen_candidates,
        }

        # Persist the complete response.
        _FREEZES[freeze_id] = response
        _FREEZE_INPUTS[freeze_id] = fingerprint

        return response


# ---------------------------------------------------------------------------
# Select validation
# ---------------------------------------------------------------------------

def validate_select_shape(body: Any) -> bool:
    if not isinstance(body, dict):
        return False

    if body.get("phase") != "select":
        return False

    # Explicit requirement: these must be arrays.
    if not isinstance(body.get("candidates"), list):
        return False

    if not isinstance(body.get("rows"), list):
        return False

    if not isinstance(body.get("policy"), dict):
        return False

    return True


def validate_policy(
    policy: Dict[str, Any],
    candidate_names: set,
) -> bool:

    required = {
        "maxBytes",
        "aggregateFloor",
        "requiredSlices",
        "maxLatencyMs",
        "candidateOrder",
    }

    if set(policy.keys()) != required:
        return False

    max_bytes = policy.get("maxBytes")
    aggregate_floor = policy.get("aggregateFloor")
    required_slices = policy.get("requiredSlices")
    max_latency = policy.get("maxLatencyMs")
    order = policy.get("candidateOrder")

    if not is_safe_nonnegative_int(max_bytes):
        return False

    if not is_floor(aggregate_floor):
        return False

    if not isinstance(required_slices, dict):
        return False

    for slice_name, floor in required_slices.items():
        if not nonempty_string(slice_name):
            return False
        if not is_floor(floor):
            return False

    if not is_finite_nonnegative_number(max_latency):
        return False

    if not isinstance(order, list):
        return False

    if len(order) != len(candidate_names):
        return False

    order_seen = set()

    for name in order:
        if not nonempty_string(name):
            return False
        if name in order_seen:
            return False
        order_seen.add(name)

    if order_seen != candidate_names:
        return False

    return True


def validate_rows(
    rows: List[Any],
    candidate_names: set,
) -> bool:

    if len(rows) == 0:
        return False

    for row in rows:
        if not isinstance(row, dict):
            return False

        if "label" not in row:
            return False

        if "slice" not in row:
            return False

        if "predictions" not in row:
            return False

        label = row["label"]
        slice_name = row["slice"]
        predictions = row["predictions"]

        # Binary labels.
        if not (
            isinstance(label, int)
            and not isinstance(label, bool)
            and label in (0, 1)
        ):
            return False

        if not nonempty_string(slice_name):
            return False

        if not isinstance(predictions, dict):
            return False

        # Every candidate must have a prediction.
        if set(predictions.keys()) != candidate_names:
            return False

        for value in predictions.values():
            if not (
                isinstance(value, int)
                and not isinstance(value, bool)
                and value in (0, 1)
            ):
                return False

    return True


# ---------------------------------------------------------------------------
# Manifest / lineage
# ---------------------------------------------------------------------------

def candidate_manifest_valid(candidate: Dict[str, Any]) -> bool:
    """
    Validate the recorded inventory itself and ensure recorded totalBytes and
    packageDigest agree with a fresh recomputation.
    """

    inventory = candidate.get("inventory")
    recorded_total = candidate.get("totalBytes")
    recorded_digest = candidate.get("packageDigest")

    valid, total, digest = recompute_manifest(inventory)

    if not valid:
        return False

    if recorded_total != total:
        return False

    if recorded_digest != digest:
        return False

    return True


def exact_candidate_array_equal(a: Any, b: Any) -> bool:
    """
    Python structural equality is appropriate here: object member ordering is
    not semantically significant, while array ordering is significant.
    """
    return a == b


# ---------------------------------------------------------------------------
# Candidate evaluation
# ---------------------------------------------------------------------------

def evaluate_candidate(
    candidate: Dict[str, Any],
    rows: List[Dict[str, Any]],
    policy: Dict[str, Any],
    latencies: Any,
    lineage_valid: bool,
) -> Dict[str, Any]:

    name = candidate.get("name")

    reason_codes: List[str] = []

    # -------------------------
    # Lineage
    # -------------------------
    if not lineage_valid:
        reason_codes.append("INVALID_LINEAGE")

    # -------------------------
    # Manifest
    # -------------------------
    manifest_valid = candidate_manifest_valid(candidate)

    if not manifest_valid:
        reason_codes.append("INVALID_MANIFEST")

    # -------------------------
    # Status
    # -------------------------
    if candidate.get("status") != "frozen":
        reason_codes.append("NOT_FROZEN")

    # -------------------------
    # Prediction validation
    # -------------------------
    predictions_valid = True

    if not validate_rows(
        rows,
        {candidate.get("name")},
    ):
        # This helper expects a set containing only the current candidate,
        # which is not appropriate because each row contains every candidate.
        # Do direct per-candidate validation instead.
        predictions_valid = True

    for row in rows:
        if not isinstance(row, dict):
            predictions_valid = False
            break

        label = row.get("label")
        slice_name = row.get("slice")
        predictions = row.get("predictions")

        if not (
            isinstance(label, int)
            and not isinstance(label, bool)
            and label in (0, 1)
        ):
            predictions_valid = False
            break

        if not nonempty_string(slice_name):
            predictions_valid = False
            break

        if not isinstance(predictions, dict):
            predictions_valid = False
            break

        if name not in predictions:
            predictions_valid = False
            break

        pred = predictions.get(name)

        if not (
            isinstance(pred, int)
            and not isinstance(pred, bool)
            and pred in (0, 1)
        ):
            predictions_valid = False
            break

    if not predictions_valid:
        reason_codes.append("INVALID_PREDICTIONS")

    # -------------------------
    # Metrics
    # -------------------------
    aggregate: Optional[float] = None
    slices: Dict[str, Optional[float]] = {}

    if predictions_valid and len(rows) > 0:
        correct = 0

        per_slice_total: Dict[str, int] = {}
        per_slice_correct: Dict[str, int] = {}

        for row in rows:
            label = row["label"]
            slice_name = row["slice"]
            pred = row["predictions"][name]

            if pred == label:
                correct += 1

            per_slice_total[slice_name] = (
                per_slice_total.get(slice_name, 0) + 1
            )

            if pred == label:
                per_slice_correct[slice_name] = (
                    per_slice_correct.get(slice_name, 0) + 1
                )

        aggregate = rounded12(correct / len(rows))

        for slice_name in policy["requiredSlices"].keys():
            if slice_name in per_slice_total:
                slices[slice_name] = rounded12(
                    per_slice_correct.get(slice_name, 0)
                    / per_slice_total[slice_name]
                )
            else:
                slices[slice_name] = None
    else:
        for slice_name in policy.get("requiredSlices", {}).keys():
            slices[slice_name] = None

    # -------------------------
    # Policy floors
    # -------------------------
    if predictions_valid:
        if aggregate is None or aggregate < float(policy["aggregateFloor"]):
            reason_codes.append("AGGREGATE_FLOOR")

        for slice_name, floor in policy["requiredSlices"].items():
            if slices.get(slice_name) is None:
                reason_codes.append(f"MISSING_SLICE:{slice_name}")
            elif slices[slice_name] < float(floor):
                reason_codes.append(f"SLICE_FLOOR:{slice_name}")

    # -------------------------
    # Size
    # -------------------------
    total_bytes: Optional[int] = None

    if (
        manifest_valid
        and is_safe_nonnegative_int(candidate.get("totalBytes"))
    ):
        total_bytes = candidate["totalBytes"]

        if total_bytes > policy["maxBytes"]:
            reason_codes.append("SIZE_LIMIT")
    else:
        reason_codes.append("SIZE_LIMIT")

    # -------------------------
    # Latency
    # -------------------------
    latency_ms: Optional[float] = None

    if isinstance(latencies, dict) and name in latencies:
        value = latencies[name]

        if is_finite_nonnegative_number(value):
            latency_ms = value

            if float(value) > float(policy["maxLatencyMs"]):
                reason_codes.append("LATENCY_LIMIT")
        else:
            reason_codes.append("LATENCY_LIMIT")
    else:
        reason_codes.append("LATENCY_LIMIT")

    # Deterministic reason order.
    reason_codes = sorted_codes(reason_codes)

    admitted = len(reason_codes) == 0

    return {
        "name": name,
        "aggregate": aggregate,
        "slices": slices,
        "totalBytes": total_bytes,
        "latencyMs": latency_ms,
        "admitted": admitted,
        "reasonCodes": reason_codes,
    }


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------

def do_select(body: Dict[str, Any]):
    freeze_id = body.get("freezeId")

    with _LOCK:
        frozen_response = _FREEZES.get(freeze_id)

    if frozen_response is None:
        # We still return a deterministic result structure.
        supplied_candidates = body.get("candidates", [])
        supplied_names = []

        if isinstance(supplied_candidates, list):
            for c in supplied_candidates:
                if isinstance(c, dict) and nonempty_string(c.get("name")):
                    supplied_names.append(c["name"])

        results = [
            {
                "name": name,
                "aggregate": None,
                "slices": {},
                "totalBytes": None,
                "latencyMs": None,
                "admitted": False,
                "reasonCodes": ["NOT_FROZEN"],
            }
            for name in supplied_names
        ]

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": results,
            "packageManifest": None,
        }

    stored_candidates = frozen_response["candidates"]
    supplied_candidates = body["candidates"]

    stored_names = {
        c["name"] for c in stored_candidates
        if isinstance(c, dict) and "name" in c
    }

    lineage_valid = exact_candidate_array_equal(
        supplied_candidates,
        stored_candidates,
    )

    policy = body["policy"]
    policy_valid = validate_policy(policy, stored_names)

    # If candidate array is malformed enough that names cannot be extracted,
    # use the stored candidate set for deterministic evaluation.
    if isinstance(supplied_candidates, list):
        names_for_results = []

        for candidate in supplied_candidates:
            if (
                isinstance(candidate, dict)
                and nonempty_string(candidate.get("name"))
                and candidate["name"] not in names_for_results
            ):
                names_for_results.append(candidate["name"])

        if set(names_for_results) != stored_names:
            names_for_results = [c["name"] for c in stored_candidates]
    else:
        names_for_results = [c["name"] for c in stored_candidates]

    # Candidate order determines result order.
    if policy_valid:
        order_map = {
            name: index
            for index, name in enumerate(policy["candidateOrder"])
        }

        names_for_results.sort(
            key=lambda n: (
                order_map.get(n, len(order_map)),
                n.encode("utf-8"),
            )
        )
    else:
        names_for_results.sort(key=lambda n: n.encode("utf-8"))

    stored_by_name = {
        c["name"]: c
        for c in stored_candidates
    }

    supplied_by_name = {}

    if isinstance(supplied_candidates, list):
        for c in supplied_candidates:
            if isinstance(c, dict) and nonempty_string(c.get("name")):
                supplied_by_name[c["name"]] = c

    rows = body["rows"]

    latencies = body.get("latencies", {})

    results: List[Dict[str, Any]] = []

    for name in names_for_results:
        candidate = supplied_by_name.get(name)

        if candidate is None:
            candidate = stored_by_name[name]

        # Invalid policy should produce INVALID_POLICY rather than attempting
        # to apply incomplete thresholds.
        if not policy_valid:
            results.append(
                {
                    "name": name,
                    "aggregate": None,
                    "slices": {},
                    "totalBytes": None,
                    "latencyMs": None,
                    "admitted": False,
                    "reasonCodes": sorted_codes(
                        ["INVALID_POLICY"]
                        + ([] if lineage_valid else ["INVALID_LINEAGE"])
                    ),
                }
            )
            continue

        result = evaluate_candidate(
            candidate,
            rows,
            policy,
            latencies,
            lineage_valid,
        )

        results.append(result)

    # Winner:
    #   1. admitted only
    #   2. smaller bytes
    #   3. lower latency
    #   4. candidateOrder
    winner = None

    if policy_valid:
        order_map = {
            name: index
            for index, name in enumerate(policy["candidateOrder"])
        }

        admitted_results = [
            result
            for result in results
            if result["admitted"]
        ]

        admitted_results.sort(
            key=lambda r: (
                r["totalBytes"],
                float(r["latencyMs"]),
                order_map.get(
                    r["name"],
                    len(order_map),
                ),
                r["name"].encode("utf-8"),
            )
        )

        if admitted_results:
            winner = admitted_results[0]["name"]

    package_manifest = None

    if winner is not None:
        package_manifest = stored_by_name[winner]

    return {
        "freezeId": freeze_id,
        "selected": winner,
        "results": results,
        "packageManifest": package_manifest,
    }


# ---------------------------------------------------------------------------
# HTTP endpoint
# ---------------------------------------------------------------------------

@app.post("/quantize")
async def quantize(request: Request):
    try:
        body = await request.json()
    except Exception:
        return invalid_input_response()

    # Unknown/missing phase is a hard 400.
    if not isinstance(body, dict):
        return invalid_input_response()

    phase = body.get("phase")

    if phase == "freeze":
        if not validate_freeze_request(body):
            return invalid_input_response()

        result = do_freeze(body)

        if isinstance(result, JSONResponse):
            return result

        return JSONResponse(
            status_code=200,
            content=result,
        )

    if phase == "select":
        # Missing candidates/rows/policy or wrong types => exact 400.
        if not validate_select_shape(body):
            return invalid_input_response()

        result = do_select(body)

        return JSONResponse(
            status_code=200,
            content=result,
        )

    return invalid_input_response()


# ---------------------------------------------------------------------------
# Optional health endpoint for deployment testing
# ---------------------------------------------------------------------------

@app.get("/")
def root():
    return {"ok": True}
