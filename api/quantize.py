import hashlib
import json
import math
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


app = FastAPI()

# Stateful storage for freeze records.
# This persists while the Vercel function instance remains warm.
FREEZES = {}


# ============================================================
# JSON / HASH HELPERS
# ============================================================

def compact_json_bytes(value: Any) -> bytes:
    """
    Exact compact UTF-8 JSON representation.
    """
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utf8_key(value: str):
    return value.encode("utf-8")


def canonical_json(value: Any) -> bytes:
    return compact_json_bytes(value)


# ============================================================
# BASIC VALIDATION HELPERS
# ============================================================

def is_nonempty_string(value) -> bool:
    return isinstance(value, str) and len(value) > 0


def is_finite_number(value) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def is_safe_nonnegative_integer(value) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 0
        and value <= 9007199254740991
    )


def unique_nonempty_strings(
    value,
    allow_empty=True,
) -> bool:
    if not isinstance(value, list):
        return False

    if not allow_empty and len(value) == 0:
        return False

    if any(not is_nonempty_string(x) for x in value):
        return False

    return len(value) == len(set(value))


def add_code(codes, code):
    if code not in codes:
        codes.append(code)


def sort_codes(codes):
    return sorted(set(codes), key=utf8_key)


# ============================================================
# FREEZE REQUEST VALIDATION
# ============================================================

def validate_freeze_request(body):
    """
    Validate only request-level constraints.

    Candidate-level problems are deliberately handled by
    freeze_candidate(), because the specification says invalid
    candidate files produce an invalid candidate with an empty
    inventory rather than rejecting the entire request.
    """

    if not isinstance(body, dict):
        return False

    if body.get("phase") != "freeze":
        return False

    freeze_id = body.get("freezeId")

    if not is_nonempty_string(freeze_id):
        return False

    if len(freeze_id) > 128:
        return False

    calibration = body.get("calibrationDigest")

    if not is_nonempty_string(calibration):
        return False

    tokenizer = body.get("tokenizerDigest")

    if not is_nonempty_string(tokenizer):
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

        if not is_nonempty_string(name):
            return False

        names.append(name)

    if len(names) != len(set(names)):
        return False

    return True


# ============================================================
# FILE INVENTORY
# ============================================================

def build_inventory(candidate):
    """
    Build the exact file inventory.

    Every file:
      - is UTF-8 encoded
      - gets exact byte length
      - gets lowercase SHA-256

    Inventory is sorted by UTF-8 filename.

    Returns:

        valid,
        inventory,
        totalBytes,
        packageDigest
    """

    files = candidate.get("files")

    if not isinstance(files, dict):
        return False, [], None, None

    if len(files) == 0:
        return False, [], None, None

    # Validate filename/content types.
    for filename, content in files.items():

        if not isinstance(filename, str):
            return False, [], None, None

        if len(filename) == 0:
            return False, [], None, None

        if not isinstance(content, str):
            return False, [], None, None

    inventory = []

    for filename in sorted(
        files.keys(),
        key=utf8_key,
    ):

        content = files[filename]

        raw = content.encode("utf-8")

        inventory.append({
            "name": filename,
            "bytes": len(raw),
            "sha256": sha256_hex(raw),
        })

    total_bytes = sum(
        item["bytes"]
        for item in inventory
    )

    package_digest = sha256_hex(
        compact_json_bytes(inventory)
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
    request_calibration_digest,
    request_tokenizer_digest,
    allowed_reasons,
):
    name = candidate.get("name")

    files_valid, inventory, total_bytes, package_digest = (
        build_inventory(candidate)
    )

    # Invalid files invalidate only this candidate.
    if not files_valid:

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

    reason_codes = []

    status = "frozen"

    unsupported_reason = candidate.get(
        "unsupportedReason"
    )

    # --------------------------------------------------------
    # Unsupported candidate
    # --------------------------------------------------------

    if (
        isinstance(unsupported_reason, str)
        and len(unsupported_reason) > 0
    ):

        if unsupported_reason in allowed_reasons:

            status = "unsupported"

        else:

            status = "invalid"

            add_code(
                reason_codes,
                "UNALLOWED_UNSUPPORTED_REASON",
            )

    # --------------------------------------------------------
    # Normal candidate
    # --------------------------------------------------------

    else:

        if candidate.get("loadable") is not True:

            status = "invalid"

            add_code(
                reason_codes,
                "NOT_LOADABLE",
            )

        if (
            candidate.get("calibrationDigest")
            != request_calibration_digest
        ):

            status = "invalid"

            add_code(
                reason_codes,
                "CALIBRATION_MISMATCH",
            )

        if (
            candidate.get("tokenizerDigest")
            != request_tokenizer_digest
        ):

            status = "invalid"

            add_code(
                reason_codes,
                "TOKENIZER_MISMATCH",
            )

    return {
        "name": name,
        "status": status,
        "inventory": inventory,
        "totalBytes": total_bytes,
        "packageDigest": package_digest,
        "reasonCodes": sort_codes(reason_codes),
    }


# ============================================================
# CREATE FREEZE RESPONSE
# ============================================================

def create_freeze_response(body):

    allowed_reasons = set(
        body["allowedUnsupportedReasons"]
    )

    candidates = []

    for candidate in body["candidates"]:

        candidates.append(
            freeze_candidate(
                candidate=candidate,
                request_calibration_digest=body[
                    "calibrationDigest"
                ],
                request_tokenizer_digest=body[
                    "tokenizerDigest"
                ],
                allowed_reasons=allowed_reasons,
            )
        )

    candidates.sort(
        key=lambda item: utf8_key(item["name"])
    )

    return {
        "freezeId": body["freezeId"],
        "candidates": candidates,
    }


# ============================================================
# MANIFEST VERIFICATION DURING SELECT
# ============================================================

def verify_manifest(candidate):
    """
    Recompute the submitted inventory's total and digest.

    We NEVER trust totalBytes or packageDigest supplied in the
    select request.
    """

    inventory = candidate.get("inventory")

    if not isinstance(inventory, list):
        return False, None, None

    rebuilt = []

    previous_name = None
    names = set()

    for item in inventory:

        if not isinstance(item, dict):
            return False, None, None

        if set(item.keys()) != {
            "name",
            "bytes",
            "sha256",
        }:
            return False, None, None

        filename = item.get("name")
        byte_count = item.get("bytes")
        digest = item.get("sha256")

        if not is_nonempty_string(filename):
            return False, None, None

        if not is_safe_nonnegative_integer(
            byte_count
        ):
            return False, None, None

        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or digest != digest.lower()
            or any(
                ch not in "0123456789abcdef"
                for ch in digest
            )
        ):
            return False, None, None

        if filename in names:
            return False, None, None

        names.add(filename)

        # Must already be sorted by UTF-8 filename.
        if previous_name is not None:

            if utf8_key(filename) <= utf8_key(
                previous_name
            ):
                return False, None, None

        previous_name = filename

        # Exact key order is name, bytes, sha256.
        rebuilt.append({
            "name": filename,
            "bytes": byte_count,
            "sha256": digest,
        })

    total_bytes = sum(
        item["bytes"]
        for item in rebuilt
    )

    package_digest = sha256_hex(
        compact_json_bytes(rebuilt)
    )

    # Submitted totals/digest are not trusted.
    if candidate.get("totalBytes") != total_bytes:
        return False, None, None

    if candidate.get("packageDigest") != package_digest:
        return False, None, None

    return (
        True,
        total_bytes,
        package_digest,
    )


# ============================================================
# POLICY VALIDATION
# ============================================================

def validate_policy(policy):

    if not isinstance(policy, dict):
        return False

    max_bytes = policy.get("maxBytes")

    if not is_safe_nonnegative_integer(
        max_bytes
    ):
        return False

    aggregate_floor = policy.get(
        "aggregateFloor"
    )

    if not is_finite_number(
        aggregate_floor
    ):
        return False

    if not 0 <= float(
        aggregate_floor
    ) <= 1:
        return False

    required_slices = policy.get(
        "requiredSlices"
    )

    if not isinstance(
        required_slices,
        dict,
    ):
        return False

    for slice_name, floor in required_slices.items():

        if not is_nonempty_string(
            slice_name
        ):
            return False

        if not is_finite_number(floor):
            return False

        if not 0 <= float(floor) <= 1:
            return False

    max_latency = policy.get(
        "maxLatencyMs"
    )

    if not is_finite_number(max_latency):
        return False

    if float(max_latency) < 0:
        return False

    candidate_order = policy.get(
        "candidateOrder"
    )

    if not unique_nonempty_strings(
        candidate_order,
        allow_empty=False,
    ):
        return False

    return True


# ============================================================
# ACCURACY
# ============================================================

def rounded_accuracy(correct, total):

    if total == 0:
        return None

    return float(
        f"{correct / total:.12f}"
    )


# ============================================================
# CANDIDATE SELECTION EVALUATION
# ============================================================

def evaluate_candidate(
    candidate,
    rows,
    policy,
    latencies,
):
    name = candidate["name"]

    reason_codes = []

    aggregate = None

    slices = {}

    total_bytes = None

    latency_ms = None

    # --------------------------------------------------------
    # LINEAGE
    # --------------------------------------------------------

    if candidate.get("status") != "frozen":

        add_code(
            reason_codes,
            "INVALID_LINEAGE",
        )

    # --------------------------------------------------------
    # MANIFEST
    # --------------------------------------------------------

    manifest_valid, manifest_bytes, _ = (
        verify_manifest(candidate)
    )

    if manifest_valid:

        total_bytes = manifest_bytes

    else:

        add_code(
            reason_codes,
            "INVALID_MANIFEST",
        )

    # --------------------------------------------------------
    # PREDICTIONS
    # --------------------------------------------------------

    predictions_valid = True

    aggregate_correct = 0

    slice_total = {}

    slice_correct = {}

    for row in rows:

        if not isinstance(row, dict):

            predictions_valid = False
            break

        if "label" not in row:

            predictions_valid = False
            break

        if "slice" not in row:

            predictions_valid = False
            break

        if not is_nonempty_string(
            row.get("slice")
        ):

            predictions_valid = False
            break

        predictions = row.get(
            "predictions"
        )

        if not isinstance(
            predictions,
            dict,
        ):

            predictions_valid = False
            break

        if name not in predictions:

            predictions_valid = False
            break

        label = row["label"]

        prediction = predictions[name]

        # Binary labels.
        if (
            isinstance(label, bool)
            or not isinstance(label, int)
            or label not in (0, 1)
        ):

            predictions_valid = False
            break

        # Binary predictions.
        if (
            isinstance(prediction, bool)
            or not isinstance(
                prediction,
                int,
            )
            or prediction not in (0, 1)
        ):

            predictions_valid = False
            break

        slice_name = row["slice"]

        slice_total[slice_name] = (
            slice_total.get(
                slice_name,
                0,
            )
            + 1
        )

        if slice_name not in slice_correct:
            slice_correct[slice_name] = 0

        if prediction == label:

            aggregate_correct += 1

            slice_correct[slice_name] += 1

    if not predictions_valid:

        add_code(
            reason_codes,
            "INVALID_PREDICTIONS",
        )

        # Invalid predictions mean aggregate and required
        # slice values cannot be validated.
        aggregate = None

        for slice_name in policy[
            "requiredSlices"
        ]:

            slices[slice_name] = None

    else:

        aggregate = rounded_accuracy(
            aggregate_correct,
            len(rows),
        )

        # Report all observed slices.
        for slice_name in sorted(
            slice_total.keys(),
            key=utf8_key,
        ):

            slices[slice_name] = (
                rounded_accuracy(
                    slice_correct[slice_name],
                    slice_total[slice_name],
                )
            )

        # ----------------------------------------------------
        # Aggregate floor
        # ----------------------------------------------------

        if (
            aggregate is None
            or aggregate
            < float(
                policy["aggregateFloor"]
            )
        ):

            add_code(
                reason_codes,
                "AGGREGATE_FLOOR",
            )

        # ----------------------------------------------------
        # Required slices
        # ----------------------------------------------------

        for (
            slice_name,
            floor,
        ) in policy[
            "requiredSlices"
        ].items():

            if slice_name not in slice_total:

                # If a required slice is absent, make its
                # reported value null.
                slices[slice_name] = None

                add_code(
                    reason_codes,
                    f"MISSING_SLICE:{slice_name}",
                )

            else:

                actual = slices[
                    slice_name
                ]

                if actual < float(floor):

                    add_code(
                        reason_codes,
                        f"SLICE_FLOOR:{slice_name}",
                    )

    # --------------------------------------------------------
    # SIZE
    # --------------------------------------------------------

    if total_bytes is not None:

        if (
            total_bytes
            > policy["maxBytes"]
        ):

            add_code(
                reason_codes,
                "SIZE_LIMIT",
            )

    # --------------------------------------------------------
    # LATENCY
    # --------------------------------------------------------

    if name not in latencies:

        # Cannot validate latency.
        latency_ms = None

        add_code(
            reason_codes,
            "LATENCY_LIMIT",
        )

    else:

        supplied_latency = latencies[name]

        if (
            is_finite_number(
                supplied_latency
            )
            and float(
                supplied_latency
            ) >= 0
        ):

            latency_ms = supplied_latency

            if (
                float(latency_ms)
                > float(
                    policy[
                        "maxLatencyMs"
                    ]
                )
            ):

                add_code(
                    reason_codes,
                    "LATENCY_LIMIT",
                )

        else:

            latency_ms = None

            add_code(
                reason_codes,
                "LATENCY_LIMIT",
            )

    # --------------------------------------------------------
    # FINAL
    # --------------------------------------------------------

    reason_codes = sort_codes(
        reason_codes
    )

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


# ============================================================
# SELECT REQUEST VALIDATION
# ============================================================

def validate_select_shape(body):

    if not isinstance(body, dict):
        return False

    if body.get("phase") != "select":
        return False

    if not is_nonempty_string(
        body.get("freezeId")
    ):
        return False

    # Explicitly required to be arrays.
    if not isinstance(
        body.get("candidates"),
        list,
    ):
        return False

    if not isinstance(
        body.get("rows"),
        list,
    ):
        return False

    # Explicitly required to be object.
    if not isinstance(
        body.get("policy"),
        dict,
    ):
        return False

    # Latencies is part of the supplied select request.
    if not isinstance(
        body.get("latencies"),
        dict,
    ):
        return False

    return True


# ============================================================
# SELECT
# ============================================================

def create_select_response(
    body,
    frozen_response,
):
    freeze_id = body["freezeId"]

    supplied_candidates = body[
        "candidates"
    ]

    frozen_candidates = frozen_response[
        "candidates"
    ]

    # --------------------------------------------------------
    # Exact candidate array equality.
    # --------------------------------------------------------

    if canonical_json(
        supplied_candidates
    ) != canonical_json(
        frozen_candidates
    ):

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None,
        }

    policy = body["policy"]

    # --------------------------------------------------------
    # Policy
    # --------------------------------------------------------

    if not validate_policy(policy):

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None,
        }

    # --------------------------------------------------------
    # Candidate names / order
    # --------------------------------------------------------

    supplied_names = [
        candidate["name"]
        for candidate in supplied_candidates
    ]

    candidate_order = policy[
        "candidateOrder"
    ]

    if len(supplied_names) != len(
        set(supplied_names)
    ):

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None,
        }

    if len(candidate_order) != len(
        set(candidate_order)
    ):

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None,
        }

    if set(supplied_names) != set(
        candidate_order
    ):

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None,
        }

    # --------------------------------------------------------
    # Latencies
    # --------------------------------------------------------

    latencies = body["latencies"]

    for name, value in latencies.items():

        if not is_nonempty_string(name):

            return {
                "freezeId": freeze_id,
                "selected": None,
                "results": [],
                "packageManifest": None,
            }

        if not is_finite_number(value):

            return {
                "freezeId": freeze_id,
                "selected": None,
                "results": [],
                "packageManifest": None,
            }

        if float(value) < 0:

            return {
                "freezeId": freeze_id,
                "selected": None,
                "results": [],
                "packageManifest": None,
            }

    # --------------------------------------------------------
    # Candidate map
    # --------------------------------------------------------

    candidate_map = {
        candidate["name"]: candidate
        for candidate in supplied_candidates
    }

    # --------------------------------------------------------
    # Results in candidateOrder
    # --------------------------------------------------------

    results = []

    for name in candidate_order:

        result = evaluate_candidate(
            candidate_map[name],
            body["rows"],
            policy,
            latencies,
        )

        results.append(result)

    # --------------------------------------------------------
    # Winner
    # --------------------------------------------------------

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
            for index, name in enumerate(
                candidate_order
            )
        }

        winner = min(
            admitted,
            key=lambda result: (
                result["totalBytes"],
                result["latencyMs"],
                order_index[
                    result["name"]
                ],
                utf8_key(
                    result["name"]
                ),
            ),
        )

        selected = winner["name"]

        package_manifest = candidate_map[
            selected
        ]

    return {
        "freezeId": freeze_id,
        "selected": selected,
        "results": results,
        "packageManifest": package_manifest,
    }


# ============================================================
# HTTP ENDPOINT
# ============================================================

@app.post("/quantize")
async def quantize(request: Request):

    try:
        body = await request.json()

    except Exception:

        print(
            "INVALID JSON REQUEST",
            flush=True,
        )

        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400,
        )

    if not isinstance(body, dict):

        print(
            "REQUEST IS NOT OBJECT:",
            repr(body),
            flush=True,
        )

        return JSONResponse(
            {"error": "INVALID_INPUT"},
            status_code=400,
        )

    phase = body.get("phase")

    # ========================================================
    # FREEZE
    # ========================================================

    if phase == "freeze":

        if not validate_freeze_request(
            body
        ):

            print(
                "INVALID FREEZE REQUEST:",
                repr(body),
                flush=True,
            )

            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400,
            )

        freeze_id = body[
            "freezeId"
        ]

        # ----------------------------------------------------
        # Freeze identity
        # ----------------------------------------------------

        fingerprint = sha256_hex(
            canonical_json(body)
        )

        # ----------------------------------------------------
        # Replay / conflict
        # ----------------------------------------------------

        if freeze_id in FREEZES:

            saved = FREEZES[
                freeze_id
            ]

            if (
                saved["fingerprint"]
                == fingerprint
            ):

                return JSONResponse(
                    saved["response"],
                    status_code=200,
                )

            return JSONResponse(
                {
                    "error":
                        "FREEZE_ID_CONFLICT"
                },
                status_code=409,
            )

        # ----------------------------------------------------
        # Construct and persist
        # ----------------------------------------------------

        response = create_freeze_response(
            body
        )

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

        if not validate_select_shape(
            body
        ):

            print(
                "INVALID SELECT REQUEST:",
                repr(body),
                flush=True,
            )

            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400,
            )

        freeze_id = body[
            "freezeId"
        ]

        # ----------------------------------------------------
        # Frozen ID must exist.
        # ----------------------------------------------------

        if freeze_id not in FREEZES:

            return JSONResponse({
                "freezeId": freeze_id,
                "selected": None,
                "results": [],
                "packageManifest": None,
            })

        frozen_response = FREEZES[
            freeze_id
        ]["response"]

        response = create_select_response(
            body,
            frozen_response,
        )

        return JSONResponse(
            response,
            status_code=200,
        )

    # ========================================================
    # UNKNOWN / MISSING PHASE
    # ========================================================

    print(
        "INVALID PHASE:",
        repr(body),
        flush=True,
    )

    return JSONResponse(
        {"error": "INVALID_INPUT"},
        status_code=400,
    )


# ============================================================
# HEALTH / ROOT
# ============================================================

@app.get("/")
async def root():
    return {
        "ok": True,
        "endpoint": "/quantize",
    }
