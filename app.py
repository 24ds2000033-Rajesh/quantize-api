from __future__ import annotations

import hashlib
import json
import math
import threading
from typing import Any, Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

FREEZES: dict[str, dict[str, Any]] = {}
FREEZE_INPUTS: dict[str, str] = {}
LOCK = threading.RLock()

MAX_SAFE_INTEGER = 9007199254740991


# ============================================================
# Generic helpers
# ============================================================

def invalid_input():
    return JSONResponse(
        status_code=400,
        content={"error": "INVALID_INPUT"},
    )


def conflict():
    return JSONResponse(
        status_code=409,
        content={"error": "FREEZE_ID_CONFLICT"},
    )


def nonempty_string(x: Any) -> bool:
    if not isinstance(x, str) or x == "":
        return False
    try:
        x.encode("utf-8")
        return True
    except UnicodeEncodeError:
        return False


def utf8_sort_key(x: str):
    return x.encode("utf-8")


def sort_codes(codes):
    return sorted(set(codes), key=utf8_sort_key)


def compact_json_bytes(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_int(x: Any) -> bool:
    return (
        isinstance(x, int)
        and not isinstance(x, bool)
        and 0 <= x <= MAX_SAFE_INTEGER
    )


def finite_nonnegative(x: Any) -> bool:
    return (
        isinstance(x, (int, float))
        and not isinstance(x, bool)
        and math.isfinite(float(x))
        and float(x) >= 0
    )


def floor_value(x: Any) -> bool:
    return (
        isinstance(x, (int, float))
        and not isinstance(x, bool)
        and math.isfinite(float(x))
        and 0 <= float(x) <= 1
    )


def round12(x: float) -> float:
    return round(float(x), 12)


def fingerprint(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


# ============================================================
# File inventory
# ============================================================

def make_inventory(files):
    if not isinstance(files, dict) or len(files) == 0:
        return False, [], None, None

    names = list(files.keys())

    if any(not isinstance(x, str) or x == "" for x in names):
        return False, [], None, None

    if len(set(names)) != len(names):
        return False, [], None, None

    inventory = []

    for name in names:
        value = files[name]

        if not isinstance(value, str):
            return False, [], None, None

        try:
            raw = value.encode("utf-8")
        except UnicodeEncodeError:
            return False, [], None, None

        inventory.append({
            "name": name,
            "bytes": len(raw),
            "sha256": sha256(raw),
        })

    inventory.sort(key=lambda x: x["name"].encode("utf-8"))

    total = sum(x["bytes"] for x in inventory)

    package = sha256(compact_json_bytes(inventory))

    return True, inventory, total, package


def validate_inventory(inventory):
    if not isinstance(inventory, list) or len(inventory) == 0:
        return False, None, None

    seen = set()
    normalized = []

    for item in inventory:
        if not isinstance(item, dict):
            return False, None, None

        if set(item.keys()) != {"name", "bytes", "sha256"}:
            return False, None, None

        name = item["name"]
        count = item["bytes"]
        digest = item["sha256"]

        if not nonempty_string(name):
            return False, None, None

        if name in seen:
            return False, None, None

        seen.add(name)

        if not safe_int(count):
            return False, None, None

        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(c not in "0123456789abcdef" for c in digest)
        ):
            return False, None, None

        normalized.append({
            "name": name,
            "bytes": count,
            "sha256": digest,
        })

    expected = sorted(
        normalized,
        key=lambda x: x["name"].encode("utf-8")
    )

    if normalized != expected:
        return False, None, None

    total = sum(x["bytes"] for x in normalized)
    package = sha256(compact_json_bytes(normalized))

    return True, total, package


# ============================================================
# Freeze
# ============================================================

def valid_freeze_shape(body):
    if not isinstance(body, dict):
        return False

    if body.get("phase") != "freeze":
        return False

    freeze_id = body.get("freezeId")

    if not nonempty_string(freeze_id):
        return False

    if len(freeze_id) > 128:
        return False

    if not nonempty_string(body.get("calibrationDigest")):
        return False

    if not nonempty_string(body.get("tokenizerDigest")):
        return False

    allowed = body.get("allowedUnsupportedReasons")

    if not isinstance(allowed, list):
        return False

    seen_reasons = set()

    for reason in allowed:
        if not nonempty_string(reason):
            return False
        if reason in seen_reasons:
            return False
        seen_reasons.add(reason)

    candidates = body.get("candidates")

    if not isinstance(candidates, list) or len(candidates) == 0:
        return False

    names = set()

    for c in candidates:
        if not isinstance(c, dict):
            return False

        name = c.get("name")

        if not nonempty_string(name):
            return False

        if name in names:
            return False

        names.add(name)

        # files must exist and be an object.
        if "files" not in c:
            return False

        if not isinstance(c["files"], dict):
            return False

    return True


def freeze_candidate(c, calibration, tokenizer, allowed):
    name = c["name"]

    ok, inventory, total, package = make_inventory(c.get("files"))

    if not ok:
        return {
            "name": name,
            "status": "invalid",
            "inventory": [],
            "totalBytes": None,
            "packageDigest": None,
            "reasonCodes": ["INVALID_INPUT"],
        }

    codes = []

    # Presence of unsupportedReason is what matters.
    if "unsupportedReason" in c:
        reason = c["unsupportedReason"]

        if not nonempty_string(reason):
            return {
                "name": name,
                "status": "invalid",
                "inventory": inventory,
                "totalBytes": total,
                "packageDigest": package,
                "reasonCodes": ["INVALID_INPUT"],
            }

        if reason in allowed:
            return {
                "name": name,
                "status": "unsupported",
                "inventory": inventory,
                "totalBytes": total,
                "packageDigest": package,
                "reasonCodes": [],
            }

        return {
            "name": name,
            "status": "invalid",
            "inventory": inventory,
            "totalBytes": total,
            "packageDigest": package,
            "reasonCodes": [
                "UNALLOWED_UNSUPPORTED_REASON"
            ],
        }

    if c.get("loadable") is not True:
        codes.append("NOT_LOADABLE")

    if c.get("calibrationDigest") != calibration:
        codes.append("CALIBRATION_MISMATCH")

    if c.get("tokenizerDigest") != tokenizer:
        codes.append("TOKENIZER_MISMATCH")

    codes = sort_codes(codes)

    return {
        "name": name,
        "status": "invalid" if codes else "frozen",
        "inventory": inventory,
        "totalBytes": total,
        "packageDigest": package,
        "reasonCodes": codes,
    }


def perform_freeze(body):
    freeze_id = body["freezeId"]
    fp = fingerprint(body)

    with LOCK:
        if freeze_id in FREEZES:
            if FREEZE_INPUTS[freeze_id] == fp:
                return FREEZES[freeze_id]

            return conflict()

        allowed = set(body["allowedUnsupportedReasons"])

        candidates = [
            freeze_candidate(
                c,
                body["calibrationDigest"],
                body["tokenizerDigest"],
                allowed,
            )
            for c in body["candidates"]
        ]

        candidates.sort(
            key=lambda x: x["name"].encode("utf-8")
        )

        result = {
            "freezeId": freeze_id,
            "candidates": candidates,
        }

        FREEZES[freeze_id] = result
        FREEZE_INPUTS[freeze_id] = fp

        return result


# ============================================================
# Select validation
# ============================================================

def valid_select_shape(body):
    if not isinstance(body, dict):
        return False

    if body.get("phase") != "select":
        return False

    if not nonempty_string(body.get("freezeId")):
        return False

    if not isinstance(body.get("candidates"), list):
        return False

    if not isinstance(body.get("rows"), list):
        return False

    if not isinstance(body.get("policy"), dict):
        return False

    return True


def valid_policy(policy, candidate_names):
    if not isinstance(policy, dict):
        return False

    if "maxBytes" not in policy:
        return False

    if "aggregateFloor" not in policy:
        return False

    if "requiredSlices" not in policy:
        return False

    if "maxLatencyMs" not in policy:
        return False

    if "candidateOrder" not in policy:
        return False

    if not safe_int(policy["maxBytes"]):
        return False

    if not floor_value(policy["aggregateFloor"]):
        return False

    if not isinstance(policy["requiredSlices"], dict):
        return False

    for name, floor in policy["requiredSlices"].items():
        if not nonempty_string(name):
            return False

        if not floor_value(floor):
            return False

    if not finite_nonnegative(policy["maxLatencyMs"]):
        return False

    order = policy["candidateOrder"]

    if not isinstance(order, list):
        return False

    if len(order) != len(candidate_names):
        return False

    seen = set()

    for name in order:
        if not nonempty_string(name):
            return False

        if name in seen:
            return False

        seen.add(name)

    return seen == candidate_names


def candidate_manifest_ok(candidate):
    ok, total, package = validate_inventory(
        candidate.get("inventory")
    )

    if not ok:
        return False

    if candidate.get("totalBytes") != total:
        return False

    if candidate.get("packageDigest") != package:
        return False

    return True


# ============================================================
# Prediction evaluation
# ============================================================

def evaluate(
    candidate,
    rows,
    policy,
    latencies,
    lineage_ok,
):
    name = candidate["name"]

    codes = []

    if not lineage_ok:
        codes.append("INVALID_LINEAGE")

    manifest_ok = candidate_manifest_ok(candidate)

    if not manifest_ok:
        codes.append("INVALID_MANIFEST")

    if candidate.get("status") != "frozen":
        codes.append("NOT_FROZEN")

    predictions_ok = True

    for row in rows:
        if not isinstance(row, dict):
            predictions_ok = False
            break

        if "label" not in row:
            predictions_ok = False
            break

        if "slice" not in row:
            predictions_ok = False
            break

        if "predictions" not in row:
            predictions_ok = False
            break

        label = row["label"]
        preds = row["predictions"]

        if not isinstance(label, int) or isinstance(label, bool):
            predictions_ok = False
            break

        if label not in (0, 1):
            predictions_ok = False
            break

        if not nonempty_string(row["slice"]):
            predictions_ok = False
            break

        if not isinstance(preds, dict):
            predictions_ok = False
            break

        if name not in preds:
            predictions_ok = False
            break

        pred = preds[name]

        if (
            not isinstance(pred, int)
            or isinstance(pred, bool)
            or pred not in (0, 1)
        ):
            predictions_ok = False
            break

    if not predictions_ok:
        codes.append("INVALID_PREDICTIONS")

    aggregate = None
    slices = {}

    if predictions_ok and len(rows) > 0:
        total_correct = 0

        slice_total = {}
        slice_correct = {}

        for row in rows:
            label = row["label"]
            slice_name = row["slice"]
            pred = row["predictions"][name]

            slice_total[slice_name] = (
                slice_total.get(slice_name, 0) + 1
            )

            if pred == label:
                total_correct += 1
                slice_correct[slice_name] = (
                    slice_correct.get(slice_name, 0) + 1
                )

        aggregate = round12(
            total_correct / len(rows)
        )

        for slice_name in policy["requiredSlices"]:
            if slice_name in slice_total:
                slices[slice_name] = round12(
                    slice_correct.get(slice_name, 0)
                    / slice_total[slice_name]
                )
            else:
                slices[slice_name] = None

    # Empty rows means metrics cannot satisfy a floor.
    if predictions_ok and len(rows) == 0:
        aggregate = None

        for slice_name in policy["requiredSlices"]:
            slices[slice_name] = None

    if predictions_ok:
        if (
            aggregate is None
            or aggregate < float(policy["aggregateFloor"])
        ):
            codes.append("AGGREGATE_FLOOR")

        for slice_name, floor in policy["requiredSlices"].items():
            value = slices.get(slice_name)

            if value is None:
                codes.append(
                    f"MISSING_SLICE:{slice_name}"
                )
            elif value < float(floor):
                codes.append(
                    f"SLICE_FLOOR:{slice_name}"
                )

    # Size
    total_bytes = None

    if (
        manifest_ok
        and safe_int(candidate.get("totalBytes"))
    ):
        total_bytes = candidate["totalBytes"]

        if total_bytes > policy["maxBytes"]:
            codes.append("SIZE_LIMIT")
    else:
        codes.append("INVALID_MANIFEST")

    # Latency
    latency = None

    if isinstance(latencies, dict) and name in latencies:
        value = latencies[name]

        if finite_nonnegative(value):
            latency = value

            if float(value) > float(policy["maxLatencyMs"]):
                codes.append("LATENCY_LIMIT")
        else:
            codes.append("LATENCY_LIMIT")
    else:
        codes.append("LATENCY_LIMIT")

    codes = sort_codes(codes)

    return {
        "name": name,
        "aggregate": aggregate,
        "slices": slices,
        "totalBytes": total_bytes,
        "latencyMs": latency,
        "admitted": len(codes) == 0,
        "reasonCodes": codes,
    }


# ============================================================
# Select
# ============================================================

def perform_select(body):
    freeze_id = body["freezeId"]

    with LOCK:
        frozen = FREEZES.get(freeze_id)

    if frozen is None:
        names = []

        for c in body["candidates"]:
            if (
                isinstance(c, dict)
                and nonempty_string(c.get("name"))
                and c["name"] not in names
            ):
                names.append(c["name"])

        names.sort(key=lambda x: x.encode("utf-8"))

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [
                {
                    "name": name,
                    "aggregate": None,
                    "slices": {},
                    "totalBytes": None,
                    "latencyMs": None,
                    "admitted": False,
                    "reasonCodes": ["NOT_FROZEN"],
                }
                for name in names
            ],
            "packageManifest": None,
        }

    stored = frozen["candidates"]
    supplied = body["candidates"]

    stored_names = {
        c["name"] for c in stored
    }

    supplied_names = []

    for c in supplied:
        if (
            isinstance(c, dict)
            and nonempty_string(c.get("name"))
            and c["name"] not in supplied_names
        ):
            supplied_names.append(c["name"])

    # Exact structural equality to the recorded response.
    lineage_ok = supplied == stored

    policy = body["policy"]
    policy_ok = valid_policy(
        policy,
        stored_names,
    )

    stored_by_name = {
        c["name"]: c
        for c in stored
    }

    supplied_by_name = {}

    for c in supplied:
        if isinstance(c, dict) and nonempty_string(c.get("name")):
            supplied_by_name[c["name"]] = c

    names = list(stored_names)

    if policy_ok:
        order_map = {
            name: i
            for i, name in enumerate(
                policy["candidateOrder"]
            )
        }

        names.sort(
            key=lambda x: (
                order_map.get(x, len(order_map)),
                x.encode("utf-8"),
            )
        )
    else:
        names.sort(key=lambda x: x.encode("utf-8"))

    results = []

    for name in names:
        candidate = supplied_by_name.get(name)

        if candidate is None:
            candidate = stored_by_name[name]

        if not policy_ok:
            results.append({
                "name": name,
                "aggregate": None,
                "slices": {},
                "totalBytes": None,
                "latencyMs": None,
                "admitted": False,
                "reasonCodes": sort_codes([
                    "INVALID_POLICY",
                    *([] if lineage_ok else ["INVALID_LINEAGE"]),
                ]),
            })
            continue

        result = evaluate(
            candidate,
            body["rows"],
            policy,
            body.get("latencies", {}),
            lineage_ok,
        )

        results.append(result)

    selected = None

    if policy_ok:
        order_map = {
            name: i
            for i, name in enumerate(
                policy["candidateOrder"]
            )
        }

        winners = [
            x for x in results
            if x["admitted"]
        ]

        winners.sort(
            key=lambda x: (
                x["totalBytes"],
                float(x["latencyMs"]),
                order_map.get(
                    x["name"],
                    len(order_map),
                ),
                x["name"].encode("utf-8"),
            )
        )

        if winners:
            selected = winners[0]["name"]

    manifest = None

    if selected is not None:
        manifest = stored_by_name[selected]

    return {
        "freezeId": freeze_id,
        "selected": selected,
        "results": results,
        "packageManifest": manifest,
    }


# ============================================================
# Endpoint
# ============================================================

@app.post("/quantize")
async def quantize(request: Request):
    try:
        body = await request.json()
    except Exception:
        return invalid_input()

    if not isinstance(body, dict):
        return invalid_input()

    phase = body.get("phase")

    if phase == "freeze":
        if not valid_freeze_shape(body):
            return invalid_input()

        result = perform_freeze(body)

        if isinstance(result, JSONResponse):
            return result

        return result

    if phase == "select":
        if not valid_select_shape(body):
            return invalid_input()

        return perform_select(body)

    return invalid_input()


@app.get("/")
def root():
    return {"ok": True}
