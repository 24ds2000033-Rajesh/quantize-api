import hashlib
import json
import math
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

# Stateful store for the lifetime of a Vercel function instance.
FREEZES = {}


# ============================================================
# BASIC HELPERS
# ============================================================

def compact_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def utf8(value: str) -> bytes:
    return value.encode("utf-8")


def nonempty_string(value) -> bool:
    return isinstance(value, str) and len(value) > 0


def finite_number(value) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def safe_integer(value) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= 9007199254740991
    )


def unique_nonempty_strings(value, allow_empty=True) -> bool:
    if not isinstance(value, list):
        return False

    if not allow_empty and len(value) == 0:
        return False

    if any(not nonempty_string(x) for x in value):
        return False

    return len(value) == len(set(value))


def sorted_codes(codes):
    return sorted(set(codes), key=utf8)


def add_code(codes, code):
    if code not in codes:
        codes.append(code)


# ============================================================
# FREEZE REQUEST VALIDATION
# ============================================================

def validate_freeze_request(body):
    """
    Only reject the entire request for top-level structural
    violations explicitly described as INVALID_INPUT.

    Candidate-level problems are handled in freeze_candidate().
    """

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

    if not unique_nonempty_strings(
        allowed,
        allow_empty=True,
    ):
        return False

    candidates = body.get("candidates")

    if not isinstance(candidates, list):
        return False

    if len(candidates) == 0:
        return False

    names = []

    for candidate in candidates:
        if not isinstance(candidate, dict):
            return False

        name = candidate.get("name")

        if not nonempty_string(name):
            return False

        names.append(name)

    if len(names) != len(set(names)):
        return False

    return True


# ============================================================
# FILE INVENTORY
# ============================================================

def calculate_inventory(candidate):
    """
    Returns:

      valid, inventory, totalBytes, packageDigest

    Invalid candidate files produce:
      [], null, null

    They do NOT reject the whole freeze request.
    """

    files = candidate.get("files")

    if not isinstance(files, dict) or len(files) == 0:
        return False, [], None, None

    # JSON object keys are unique by definition.
    # Filenames must be strings and non-empty.
    for filename in files:
        if not isinstance(filename, str):
            return False, [], None, None

        if filename == "":
            return False, [], None, None

        if not isinstance(files[filename], str):
            return False, [], None, None

    inventory = []

    for filename in sorted(files.keys(), key=utf8):
        content = files[filename]

        raw = content.encode("utf-8")

        inventory.append({
            "name": filename,
            "bytes": len(raw),
            "sha256": sha256_bytes(raw),
        })

    total_bytes = sum(
        item["bytes"]
        for item in inventory
    )

    package_digest = sha256_bytes(
        compact_json(inventory)
    )

    return (
        True,
        inventory,
        total_bytes,
        package_digest,
    )


# ============================================================
# FREEZE CANDIDATE
# ============================================================

def freeze_candidate(
    candidate,
    request_calibration,
    request_tokenizer,
    allowed_reasons,
):
    name = candidate.get("name")

    files_ok, inventory, total_bytes, package_digest = (
        calculate_inventory(candidate)
    )

    if not files_ok:
        return {
            "name": name,
            "status": "invalid",
            "inventory": [],
            "totalBytes": None,
            "packageDigest": None,
            "reasonCodes": [
                "INVALID_INPUT"
            ],
        }

    codes = []
    status = "frozen"

    unsupported_reason = candidate.get(
        "unsupportedReason"
    )

    # A reason makes the candidate unsupported only if
    # that reason is explicitly allowed.
    if (
        isinstance(unsupported_reason, str)
        and len(unsupported_reason) > 0
    ):
        if unsupported_reason in allowed_reasons:
            status = "unsupported"
        else:
            status = "invalid"
            add_code(
                codes,
                "UNALLOWED_UNSUPPORTED_REASON",
            )

    else:
        # No unsupported reason -> candidate must be loadable
        # and match both lineage digests.
        if candidate.get("loadable") is not True:
            status = "invalid"
            add_code(
                codes,
                "NOT_LOADABLE",
            )

        if candidate.get("calibrationDigest") != request_calibration:
            status = "invalid"
            add_code(
                codes,
                "CALIBRATION_MISMATCH",
            )

        if candidate.get("tokenizerDigest") != request_tokenizer:
            status = "invalid"
            add_code(
                codes,
                "TOKENIZER_MISMATCH",
            )

    return {
        "name": name,
        "status": status,
        "inventory": inventory,
        "totalBytes": total_bytes,
        "packageDigest": package_digest,
        "reasonCodes": sorted_codes(codes),
    }


# ============================================================
# FREEZE
# ============================================================

def create_freeze_response(body):
    allowed = set(
        body["allowedUnsupportedReasons"]
    )

    candidates = []

    for candidate in body["candidates"]:
        candidates.append(
            freeze_candidate(
                candidate,
                body["calibrationDigest"],
                body["tokenizerDigest"],
                allowed,
            )
        )

    candidates.sort(
        key=lambda candidate: utf8(candidate["name"])
    )

    return {
        "freezeId": body["freezeId"],
        "candidates": candidates,
    }


# ============================================================
# MANIFEST VALIDATION DURING SELECT
# ============================================================

def verify_manifest(candidate):
    inventory = candidate.get("inventory")

    if not isinstance(inventory, list):
        return False, None, None

    rebuilt = []
    names = []

    previous_name = None

    for item in inventory:

        if not isinstance(item, dict):
            return False, None, None

        # Exact inventory key set.
        if set(item.keys()) != {
            "name",
            "bytes",
            "sha256",
        }:
            return False, None, None

        name = item.get("name")
        byte_count = item.get("bytes")
        digest = item.get("sha256")

        if not nonempty_string(name):
            return False, None, None

        if not safe_integer(byte_count):
            return False, None, None

        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or digest != digest.lower()
            or any(
                c not in "0123456789abcdef"
                for c in digest
            )
        ):
            return False, None, None

        if previous_name is not None:
            if utf8(name) <= utf8(previous_name):
                return False, None, None

        previous_name = name

        if name in names:
            return False, None, None

        names.append(name)

        rebuilt.append({
            "name": name,
            "bytes": byte_count,
            "sha256": digest,
        })

    total = sum(
        item["bytes"]
        for item in rebuilt
    )

    digest = sha256_bytes(
        compact_json(rebuilt)
    )

    if candidate.get("totalBytes") != total:
        return False, None, None

    if candidate.get("packageDigest") != digest:
        return False, None, None

    return True, total, digest


# ============================================================
# POLICY
# ============================================================

def validate_policy(policy):
    if not isinstance(policy, dict):
        return False

    if not safe_integer(
        policy.get("maxBytes")
    ):
        return False

    if not finite_number(
        policy.get("aggregateFloor")
    ):
        return False

    if not 0 <= float(
        policy["aggregateFloor"]
    ) <= 1:
        return False

    required = policy.get("requiredSlices")

    if not isinstance(required, dict):
        return False

    for slice_name, floor in required.items():

        if not nonempty_string(slice_name):
            return False

        if not finite_number(floor):
            return False

        if not 0 <= float(floor) <= 1:
            return False

    if not finite_number(
        policy.get("maxLatencyMs")
    ):
        return False

    if float(policy["maxLatencyMs"]) < 0:
        return False

    order = policy.get("candidateOrder")

    if not unique_nonempty_strings(
        order,
        allow_empty=False,
    ):
        return False

    return True


# ============================================================
# PREDICTIONS
# ============================================================

def rounded_accuracy(correct, total):
    if total == 0:
        return None

    return float(
        f"{correct / total:.12f}"
    )


def calculate_candidate(
    candidate,
    rows,
    policy,
    latencies,
):
    name = candidate["name"]

    codes = []

    aggregate = None
    slices = {}
    total_bytes = None
    latency_ms = None

    # --------------------------------------------------------
    # lineage
    # --------------------------------------------------------

    if candidate.get("status") != "frozen":
        add_code(
            codes,
            "INVALID_LINEAGE",
        )

    # --------------------------------------------------------
    # manifest
    # --------------------------------------------------------

    manifest_ok, total, _ = verify_manifest(
        candidate
    )

    if manifest_ok:
        total_bytes = total
    else:
        add_code(
            codes,
            "INVALID_MANIFEST",
        )

    # --------------------------------------------------------
    # predictions
    # --------------------------------------------------------

    predictions_valid = True

    aggregate_correct = 0

    slice_totals = {}
    slice_correct = {}

    for row in rows:

        if not isinstance(row, dict):
            predictions_valid = False
            break

        if "label" not in row:
            predictions_valid = False
            break

        if not isinstance(
            row.get("predictions"),
            dict,
        ):
            predictions_valid = False
            break

        if name not in row["predictions"]:
            predictions_valid = False
            break

        label = row["label"]
        prediction = row["predictions"][name]

        # Binary prediction.
        if (
            isinstance(prediction, bool)
            or not isinstance(prediction, int)
            or prediction not in (0, 1)
        ):
            predictions_valid = False
            break

        if (
            isinstance(label, bool)
            or not isinstance(label, int)
            or label not in (0, 1)
        ):
            predictions_valid = False
            break

        slice_name = row.get("slice")

        if not nonempty_string(slice_name):
            predictions_valid = False
            break

        slice_totals[slice_name] = (
            slice_totals.get(slice_name, 0) + 1
        )

        slice_correct.setdefault(
            slice_name,
            0,
        )

        if prediction == label:
            aggregate_correct += 1
            slice_correct[slice_name] += 1

    if not predictions_valid:

        add_code(
            codes,
            "INVALID_PREDICTIONS",
        )

        aggregate = None
        slices = {}

    else:

        aggregate = rounded_accuracy(
            aggregate_correct,
            len(rows),
        )

        for slice_name in sorted(
            slice_totals.keys(),
            key=utf8,
        ):
            slices[slice_name] = rounded_accuracy(
                slice_correct[slice_name],
                slice_totals[slice_name],
            )

        # ----------------------------------------------------
        # aggregate floor
        # ----------------------------------------------------

        if (
            aggregate is None
            or aggregate < float(
                policy["aggregateFloor"]
            )
        ):
            add_code(
                codes,
                "AGGREGATE_FLOOR",
            )

        # ----------------------------------------------------
        # required slices
        # ----------------------------------------------------

        for (
            slice_name,
            floor,
        ) in policy["requiredSlices"].items():

            if slice_name not in slice_totals:

                add_code(
                    codes,
                    f"MISSING_SLICE:{slice_name}",
                )

            elif (
                slices[slice_name]
                < float(floor)
            ):

                add_code(
                    codes,
                    f"SLICE_FLOOR:{slice_name}",
                )

    # --------------------------------------------------------
    # size
    # --------------------------------------------------------

    if total_bytes is not None:
        if total_bytes > policy["maxBytes"]:
            add_code(
                codes,
                "SIZE_LIMIT",
            )

    # --------------------------------------------------------
    # latency
    # --------------------------------------------------------

    if name not in latencies:

        add_code(
            codes,
            "LATENCY_LIMIT",
        )

    else:

        value = latencies[name]

        if (
            finite_number(value)
            and float(value) >= 0
        ):

            latency_ms = value

            if (
                float(value)
                > float(policy["maxLatencyMs"])
            ):
                add_code(
                    codes,
                    "LATENCY_LIMIT",
                )

        else:

            add_code(
                codes,
                "LATENCY_LIMIT",
            )

    codes = sorted_codes(codes)

    return {
        "name": name,
        "aggregate": aggregate,
        "slices": slices,
        "totalBytes": total_bytes,
        "latencyMs": latency_ms,
        "admitted": len(codes) == 0,
        "reasonCodes": codes,
    }


# ============================================================
# SELECT
# ============================================================

def select_response(body, frozen):
    candidates = body["candidates"]
    policy = body["policy"]
    rows = body["rows"]
    latencies = body.get("latencies", {})

    # The candidate array must be EXACTLY the frozen array.
    if compact_json(candidates) != compact_json(
        frozen["candidates"]
    ):
        return {
            "freezeId": body["freezeId"],
            "selected": None,
            "results": [],
            "packageManifest": None,
        }

    if not validate_policy(policy):
        return {
            "freezeId": body["freezeId"],
            "selected": None,
            "results": [],
            "packageManifest": None,
        }

    names = [
        candidate.get("name")
        for candidate in candidates
    ]

    order = policy["candidateOrder"]

    # Same unique candidate set.
    if (
        len(names) != len(set(names))
        or len(order) != len(set(order))
        or set(names) != set(order)
    ):
        return {
            "freezeId": body["freezeId"],
            "selected": None,
            "results": [],
            "packageManifest": None,
        }

    # Validate latency map.
    if not isinstance(latencies, dict):
        latencies = {}

    for name, value in latencies.items():
        if not nonempty_string(name):
            return {
                "freezeId": body["freezeId"],
                "selected": None,
                "results": [],
                "packageManifest": None,
            }

        if not finite_number(value):
            return {
                "freezeId": body["freezeId"],
                "selected": None,
                "results": [],
                "packageManifest": None,
            }

        if float(value) < 0:
            return {
                "freezeId": body["freezeId"],
                "selected": None,
                "results": [],
                "packageManifest": None,
            }

    candidate_map = {
        candidate["name"]: candidate
        for candidate in candidates
    }

    results = []

    # Explicit candidateOrder determines result order.
    for name in order:
        results.append(
            calculate_candidate(
                candidate_map[name],
                rows,
                policy,
                latencies,
            )
        )

    admitted = [
        result
        for result in results
        if result["admitted"]
    ]

    selected = None
    package_manifest = None

    if admitted:

        order_index = {
            name: index
            for index, name in enumerate(order)
        }

        winner = min(
            admitted,
            key=lambda result: (
                result["totalBytes"],
                result["latencyMs"],
                order_index[result["name"]],
                utf8(result["name"]),
            ),
        )

        selected = winner["name"]
        package_manifest = candidate_map[selected]

    return {
        "freezeId": body["freezeId"],
        "selected": selected,
        "results": results,
        "packageManifest": package_manifest,
    }


# ============================================================
# ENDPOINT
# ============================================================

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

    # ========================================================
    # FREEZE
    # ========================================================

    if phase == "freeze":

        if not validate_freeze_request(body):
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400,
            )

        freeze_id = body["freezeId"]

        # Exact request identity.
        fingerprint = sha256_bytes(
            compact_json(body)
        )

        # Replay.
        if freeze_id in FREEZES:

            saved = FREEZES[freeze_id]

            if saved["fingerprint"] == fingerprint:
                return JSONResponse(
                    saved["response"],
                    status_code=200,
                )

            return JSONResponse(
                {"error": "FREEZE_ID_CONFLICT"},
                status_code=409,
            )

        response = create_freeze_response(body)

        FREEZES[freeze_id] = {
            "fingerprint": fingerprint,
            "response": response,
        }

        return JSONResponse(
            response,
            status_code=200,
        )

    # ========================================================
    # SELECT
    # ========================================================

    if phase == "select":

        # Explicit requirement:
        # missing/non-array candidates or rows, or
        # missing/non-object policy -> HTTP 400.
        if (
            not isinstance(
                body.get("candidates"),
                list,
            )
            or not isinstance(
                body.get("rows"),
                list,
            )
            or not isinstance(
                body.get("policy"),
                dict,
            )
        ):
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400,
            )

        if not nonempty_string(
            body.get("freezeId")
        ):
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400,
            )

        freeze_id = body["freezeId"]

        # NOT_FROZEN is a selection result, not HTTP 400.
        if freeze_id not in FREEZES:
            return JSONResponse({
                "freezeId": freeze_id,
                "selected": None,
                "results": [],
                "packageManifest": None,
            })

        response = select_response(
            body,
            FREEZES[freeze_id]["response"],
        )

        return JSONResponse(
            response,
            status_code=200,
        )

    # Missing/unknown phase.
    return JSONResponse(
        {"error": "INVALID_INPUT"},
        status_code=400,
    )


@app.get("/")
async def root():
    return {
        "ok": True,
        "endpoint": "/quantize",
    }
