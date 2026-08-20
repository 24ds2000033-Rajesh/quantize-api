import hashlib
import json
import math
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


app = FastAPI()

# Stateful storage for the lifetime of this serverless instance.
FREEZES = {}


# ---------------------------------------------------------------------
# JSON / UTF-8 helpers
# ---------------------------------------------------------------------

def compact_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utf8_key(value: str):
    return value.encode("utf-8")


def sorted_utf8_strings(values):
    return sorted(values, key=utf8_key)


def add_code(codes, code):
    if code not in codes:
        codes.append(code)


def sorted_codes(codes):
    return sorted(set(codes), key=utf8_key)


# ---------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------

def is_string(value):
    return isinstance(value, str)


def is_nonempty_string(value):
    return isinstance(value, str) and len(value) > 0


def is_finite_number(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def is_safe_nonnegative_integer(value):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 0
        and value <= 9007199254740991
    )


def unique_string_array(value, allow_empty=True):
    if not isinstance(value, list):
        return False

    if not allow_empty and len(value) == 0:
        return False

    if not all(is_nonempty_string(x) for x in value):
        return False

    return len(set(value)) == len(value)


def valid_digest(value):
    return is_nonempty_string(value)


# ---------------------------------------------------------------------
# Candidate manifest
# ---------------------------------------------------------------------

def build_inventory(candidate):
    """
    Returns:
        valid_files, inventory, total_bytes, package_digest
    """

    files = candidate.get("files")

    if not isinstance(files, dict) or len(files) == 0:
        return False, [], None, None

    # Object keys are strings by JSON definition, but validate anyway.
    names = list(files.keys())

    if any(not isinstance(name, str) or name == "" for name in names):
        return False, [], None, None

    if len(names) != len(set(names)):
        return False, [], None, None

    inventory = []

    for filename in sorted(names, key=utf8_key):
        content = files[filename]

        # JSON strings are Unicode. Encode directly as UTF-8.
        if not isinstance(content, str):
            return False, [], None, None

        raw = content.encode("utf-8")

        inventory.append({
            "name": filename,
            "bytes": len(raw),
            "sha256": sha256_bytes(raw),
        })

    total = sum(item["bytes"] for item in inventory)

    package_digest = sha256_bytes(compact_json_bytes(inventory))

    return True, inventory, total, package_digest


# ---------------------------------------------------------------------
# Freeze
# ---------------------------------------------------------------------

def validate_freeze_request(body):
    if not isinstance(body, dict):
        return False

    if body.get("phase") != "freeze":
        return False

    freeze_id = body.get("freezeId")

    if not is_nonempty_string(freeze_id):
        return False

    if len(freeze_id) > 128:
        return False

    if not valid_digest(body.get("calibrationDigest")):
        return False

    if not valid_digest(body.get("tokenizerDigest")):
        return False

    allowed = body.get("allowedUnsupportedReasons")

    if not unique_string_array(allowed, allow_empty=True):
        return False

    candidates = body.get("candidates")

    if not isinstance(candidates, list) or len(candidates) == 0:
        return False

    names = []

    for candidate in candidates:
        if not isinstance(candidate, dict):
            return False

        name = candidate.get("name")

        if not is_nonempty_string(name):
            return False

        names.append(name)

    if len(names) != len(set(names)):
        return False

    return True


def freeze_response(body):
    request_calibration = body["calibrationDigest"]
    request_tokenizer = body["tokenizerDigest"]
    allowed_reasons = set(body["allowedUnsupportedReasons"])

    result_candidates = []

    for candidate in body["candidates"]:
        name = candidate["name"]

        inventory_valid, inventory, total_bytes, package_digest = (
            build_inventory(candidate)
        )

        reason_codes = []
        status = "frozen"

        if not inventory_valid:
            status = "invalid"
            add_code(reason_codes, "INVALID_INPUT")

            result_candidates.append({
                "name": name,
                "status": status,
                "inventory": [],
                "totalBytes": None,
                "packageDigest": None,
                "reasonCodes": sorted_codes(reason_codes),
            })
            continue

        unsupported_reason = candidate.get("unsupportedReason")

        if is_nonempty_string(unsupported_reason):
            if unsupported_reason in allowed_reasons:
                status = "unsupported"
            else:
                status = "invalid"
                add_code(
                    reason_codes,
                    "UNALLOWED_UNSUPPORTED_REASON",
                )
        else:
            if candidate.get("loadable") is not True:
                status = "invalid"
                add_code(reason_codes, "NOT_LOADABLE")

            if candidate.get("calibrationDigest") != request_calibration:
                status = "invalid"
                add_code(reason_codes, "CALIBRATION_MISMATCH")

            if candidate.get("tokenizerDigest") != request_tokenizer:
                status = "invalid"
                add_code(reason_codes, "TOKENIZER_MISMATCH")

        result_candidates.append({
            "name": name,
            "status": status,
            "inventory": inventory,
            "totalBytes": total_bytes,
            "packageDigest": package_digest,
            "reasonCodes": sorted_codes(reason_codes),
        })

    result_candidates.sort(key=lambda x: utf8_key(x["name"]))

    return {
        "freezeId": body["freezeId"],
        "candidates": result_candidates,
    }


# ---------------------------------------------------------------------
# Freeze replay / equality
# ---------------------------------------------------------------------

def canonical_request(value):
    return compact_json_bytes(value)


# ---------------------------------------------------------------------
# Select validation
# ---------------------------------------------------------------------

def validate_select_shape(body):
    if not isinstance(body, dict):
        return False

    if body.get("phase") != "select":
        return False

    if not is_nonempty_string(body.get("freezeId")):
        return False

    if not isinstance(body.get("candidates"), list):
        return False

    if not isinstance(body.get("rows"), list):
        return False

    if not isinstance(body.get("policy"), dict):
        return False

    return True


def validate_policy(policy):
    required = [
        "maxBytes",
        "aggregateFloor",
        "requiredSlices",
        "maxLatencyMs",
        "candidateOrder",
    ]

    if any(key not in policy for key in required):
        return False

    if not is_safe_nonnegative_integer(policy["maxBytes"]):
        return False

    if not is_finite_number(policy["aggregateFloor"]):
        return False

    if not 0 <= float(policy["aggregateFloor"]) <= 1:
        return False

    if not isinstance(policy["requiredSlices"], dict):
        return False

    for name, floor in policy["requiredSlices"].items():
        if not is_nonempty_string(name):
            return False

        if not is_finite_number(floor):
            return False

        if not 0 <= float(floor) <= 1:
            return False

    if not is_finite_number(policy["maxLatencyMs"]):
        return False

    if float(policy["maxLatencyMs"]) < 0:
        return False

    if not unique_string_array(
        policy["candidateOrder"],
        allow_empty=False,
    ):
        return False

    return True


def validate_rows(rows):
    if not isinstance(rows, list):
        return False

    for row in rows:
        if not isinstance(row, dict):
            return False

        if "label" not in row:
            return False

        if "slice" not in row or not is_nonempty_string(row["slice"]):
            return False

        if "predictions" not in row:
            return False

        if not isinstance(row["predictions"], dict):
            return False

    return True


def validate_latency_map(latencies):
    if not isinstance(latencies, dict):
        return False

    for name, value in latencies.items():
        if not is_nonempty_string(name):
            return False

        if not is_finite_number(value):
            return False

        if float(value) < 0:
            return False

    return True


def recompute_candidate_manifest(candidate):
    """
    Recompute manifest from the submitted inventory.

    Returns:
        valid, total_bytes, package_digest
    """

    if not isinstance(candidate, dict):
        return False, None, None

    inventory = candidate.get("inventory")

    if not isinstance(inventory, list):
        return False, None, None

    previous_name = None
    normalized = []

    for item in inventory:
        if not isinstance(item, dict):
            return False, None, None

        if set(item.keys()) != {"name", "bytes", "sha256"}:
            return False, None, None

        name = item.get("name")
        byte_count = item.get("bytes")
        digest = item.get("sha256")

        if not is_nonempty_string(name):
            return False, None, None

        if not is_safe_nonnegative_integer(byte_count):
            return False, None, None

        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or digest.lower() != digest
            or any(c not in "0123456789abcdef" for c in digest)
        ):
            return False, None, None

        if previous_name is not None:
            if utf8_key(name) <= utf8_key(previous_name):
                return False, None, None

        previous_name = name

        normalized.append({
            "name": name,
            "bytes": byte_count,
            "sha256": digest,
        })

    names = [x["name"] for x in normalized]

    if len(names) != len(set(names)):
        return False, None, None

    total = sum(x["bytes"] for x in normalized)
    digest = sha256_bytes(compact_json_bytes(normalized))

    return True, total, digest


def rounded_accuracy(correct, total):
    if total == 0:
        return None

    # Python's formatting gives deterministic decimal rounding for
    # normal finite ratios. Convert through decimal string to avoid
    # exposing more precision than requested.
    return float(f"{correct / total:.12f}")


def calculate_candidate_result(
    candidate,
    candidate_name,
    rows,
    policy,
    latencies,
):
    reason_codes = []

    aggregate = None
    slices = {}
    total_bytes = None
    latency_ms = None

    # Manifest validation
    manifest_valid, recomputed_bytes, recomputed_digest = (
        recompute_candidate_manifest(candidate)
    )

    recorded_bytes = candidate.get("totalBytes")
    recorded_digest = candidate.get("packageDigest")

    if not manifest_valid:
        add_code(reason_codes, "INVALID_MANIFEST")
    else:
        if (
            not is_safe_nonnegative_integer(recorded_bytes)
            or recorded_bytes != recomputed_bytes
            or not is_nonempty_string(recorded_digest)
            or recorded_digest != recomputed_digest
        ):
            add_code(reason_codes, "INVALID_MANIFEST")
        else:
            total_bytes = recomputed_bytes

    # Frozen lineage/status
    status = candidate.get("status")

    if status not in ("frozen", "unsupported", "invalid"):
        add_code(reason_codes, "INVALID_LINEAGE")
    elif status != "frozen":
        add_code(reason_codes, "INVALID_LINEAGE")

    # Predictions
    prediction_valid = True

    aggregate_correct = 0

    slice_correct = {}
    slice_total = {}

    required_slices = policy["requiredSlices"]

    for row in rows:
        if candidate_name not in row["predictions"]:
            prediction_valid = False
            break

        prediction = row["predictions"][candidate_name]
        label = row["label"]

        # Binary prediction: exactly 0 or 1, excluding bool.
        if (
            isinstance(prediction, bool)
            or not isinstance(prediction, int)
            or prediction not in (0, 1)
        ):
            prediction_valid = False
            break

        if (
            isinstance(label, bool)
            or not isinstance(label, int)
            or label not in (0, 1)
        ):
            prediction_valid = False
            break

        if prediction == label:
            aggregate_correct += 1

        slice_name = row["slice"]

        if slice_name not in slice_total:
            slice_total[slice_name] = 0
            slice_correct[slice_name] = 0

        slice_total[slice_name] += 1

        if prediction == label:
            slice_correct[slice_name] += 1

    if not prediction_valid:
        add_code(reason_codes, "INVALID_PREDICTIONS")
        aggregate = None
        slices = {}
    else:
        aggregate = rounded_accuracy(
            aggregate_correct,
            len(rows),
        )

        for slice_name in sorted_utf8_strings(slice_total.keys()):
            slices[slice_name] = rounded_accuracy(
                slice_correct[slice_name],
                slice_total[slice_name],
            )

        # Aggregate floor
        if aggregate is not None:
            if aggregate < float(policy["aggregateFloor"]):
                add_code(reason_codes, "AGGREGATE_FLOOR")

        # Required slices
        for slice_name in required_slices:
            if slice_name not in slice_total:
                add_code(
                    reason_codes,
                    f"MISSING_SLICE:{slice_name}",
                )
            else:
                actual = slices[slice_name]
                floor = float(required_slices[slice_name])

                if actual < floor:
                    add_code(
                        reason_codes,
                        f"SLICE_FLOOR:{slice_name}",
                    )

    # Latency
    if candidate_name in latencies:
        value = latencies[candidate_name]

        if is_finite_number(value) and float(value) >= 0:
            latency_ms = value

            if float(value) > float(policy["maxLatencyMs"]):
                add_code(reason_codes, "LATENCY_LIMIT")
    else:
        # Missing latency cannot be validated.
        latency_ms = None
        add_code(reason_codes, "LATENCY_LIMIT")

    # Size
    if total_bytes is not None:
        if total_bytes > policy["maxBytes"]:
            add_code(reason_codes, "SIZE_LIMIT")
    else:
        # Invalid manifest prevents size validation but does not add
        # SIZE_LIMIT.
        pass

    admitted = len(reason_codes) == 0

    return {
        "name": candidate_name,
        "aggregate": aggregate,
        "slices": slices,
        "totalBytes": total_bytes,
        "latencyMs": latency_ms,
        "admitted": admitted,
        "reasonCodes": sorted_codes(reason_codes),
    }


# ---------------------------------------------------------------------
# Select
# ---------------------------------------------------------------------

def select_response(body, frozen_response):
    freeze_id = body["freezeId"]

    supplied_candidates = body["candidates"]
    frozen_candidates = frozen_response["candidates"]

    supplied_names = [x.get("name") for x in supplied_candidates]
    frozen_names = [x.get("name") for x in frozen_candidates]

    # Candidate set and exact stored array must match.
    if canonical_request(supplied_candidates) != canonical_request(
        frozen_candidates
    ):
        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None,
        }, "INVALID_LINEAGE"

    policy = body["policy"]

    if not validate_policy(policy):
        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None,
        }, "INVALID_POLICY"

    if len(supplied_names) != len(set(supplied_names)):
        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None,
        }, "INVALID_POLICY"

    order = policy["candidateOrder"]

    if set(supplied_names) != set(order):
        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None,
        }, "INVALID_POLICY"

    if not validate_rows(body["rows"]):
        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None,
        }, "INVALID_POLICY"

    if not validate_latency_map(body["latencies"]):
        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None,
        }, "INVALID_POLICY"

    # Map by name.
    candidate_map = {
        candidate["name"]: candidate
        for candidate in supplied_candidates
    }

    # Required slices must be nonempty strings and unique via JSON object keys.
    for slice_name in policy["requiredSlices"]:
        if not is_nonempty_string(slice_name):
            return {
                "freezeId": freeze_id,
                "selected": None,
                "results": [],
                "packageManifest": None,
            }, "INVALID_POLICY"

    results_by_name = {}

    for name in order:
        candidate = candidate_map[name]

        results_by_name[name] = calculate_candidate_result(
            candidate=candidate,
            candidate_name=name,
            rows=body["rows"],
            policy=policy,
            latencies=body["latencies"],
        )

    # Results must be in candidateOrder, using UTF-8 name fallback.
    result_names = list(order)

    result_names = sorted(
        result_names,
        key=lambda n: (
            order.index(n),
            utf8_key(n),
        ),
    )

    results = [results_by_name[name] for name in result_names]

    admitted_names = [
        name
        for name in result_names
        if results_by_name[name]["admitted"]
    ]

    selected = None
    package_manifest = None

    if admitted_names:
        order_index = {
            name: index
            for index, name in enumerate(order)
        }

        selected = min(
            admitted_names,
            key=lambda name: (
                results_by_name[name]["totalBytes"],
                results_by_name[name]["latencyMs"],
                order_index[name],
                utf8_key(name),
            ),
        )

        package_manifest = candidate_map[selected]

    return {
        "freezeId": freeze_id,
        "selected": selected,
        "results": results,
        "packageManifest": package_manifest,
    }, None


# ---------------------------------------------------------------------
# HTTP endpoint
# ---------------------------------------------------------------------

@app.post("/quantize")
async def quantize(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400,
        )

    if not isinstance(body, dict):
        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400,
        )

    phase = body.get("phase")

    # ================================================================
    # FREEZE
    # ================================================================
    if phase == "freeze":
        if not validate_freeze_request(body):
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400,
            )

        freeze_id = body["freezeId"]

        # Canonical representation used only for conflict detection.
        request_fingerprint = sha256_bytes(
            canonical_request(body)
        )

        existing = FREEZES.get(freeze_id)

        if existing is not None:
            if existing["fingerprint"] == request_fingerprint:
                return JSONResponse(
                    existing["response"],
                    status_code=200,
                )

            return JSONResponse(
                {"error": "FREEZE_ID_CONFLICT"},
                status_code=409,
            )

        response = freeze_response(body)

        FREEZES[freeze_id] = {
            "fingerprint": request_fingerprint,
            "response": response,
        }

        return JSONResponse(response, status_code=200)

    # ================================================================
    # SELECT
    # ================================================================
    if phase == "select":
        if not validate_select_shape(body):
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400,
            )

        freeze_id = body["freezeId"]

        frozen = FREEZES.get(freeze_id)

        if frozen is None:
            # The response shape for selection is still returned.
            response = {
                "freezeId": freeze_id,
                "selected": None,
                "results": [],
                "packageManifest": None,
            }

            response["reasonCodes"] = ["NOT_FROZEN"]

            return JSONResponse(response, status_code=200)

        response, immediate_error = select_response(
            body,
            frozen["response"],
        )

        if immediate_error is not None:
            # Selection validation failures are represented through the
            # candidate/result contract rather than HTTP 400.
            response["reasonCodes"] = sorted_codes(
                [immediate_error]
            )

        return JSONResponse(response, status_code=200)

    # Unknown / missing phase.
    return JSONResponse(
        {"error": "INVALID_INPUT"},
        status_code=400,
    )


# Optional health check.
@app.get("/")
async def root():
    return {
        "ok": True,
        "endpoint": "/quantize",
    }
