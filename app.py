from __future__ import annotations

import hashlib
import json
import math
import threading
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


app = FastAPI(title="Quantize Candidate Admission API")

# Stateful store.
# This persists while the Vercel function instance remains warm.
_FREEZES: dict[str, dict[str, Any]] = {}
_FREEZE_FINGERPRINTS: dict[str, str] = {}
_LOCK = threading.RLock()

MAX_SAFE_INTEGER = 9007199254740991


# ============================================================
# BASIC HELPERS
# ============================================================

def error_invalid_input():
    return JSONResponse(
        status_code=400,
        content={"error": "INVALID_INPUT"},
    )


def error_freeze_conflict():
    return JSONResponse(
        status_code=409,
        content={"error": "FREEZE_ID_CONFLICT"},
    )


def nonempty_string(value: Any) -> bool:
    if not isinstance(value, str):
        return False

    if len(value) == 0:
        return False

    try:
        value.encode("utf-8")
        return True
    except UnicodeEncodeError:
        return False


def utf8_key(value: str):
    return value.encode("utf-8")


def sort_utf8(values):
    return sorted(values, key=utf8_key)


def sort_codes(codes):
    return sorted(set(codes), key=utf8_key)


def compact_json_bytes(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_nonnegative_integer(value: Any) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 0
        and value <= MAX_SAFE_INTEGER
    )


def finite_nonnegative(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and float(value) >= 0
    )


def valid_floor(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and 0.0 <= float(value) <= 1.0
    )


def round12(value: float) -> float:
    return round(float(value), 12)


def request_fingerprint(value: Any) -> str:
    """
    Used only for detecting whether the same freezeId is being replayed
    with identical JSON content.

    Object key ordering is ignored.
    Array ordering is preserved.
    """
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


# ============================================================
# FILE INVENTORY
# ============================================================

def build_inventory(files):
    """
    Return:

        valid,
        inventory,
        totalBytes,
        packageDigest

    Inventory is always sorted by UTF-8 filename.
    """

    if not isinstance(files, dict):
        return False, [], None, None

    if len(files) == 0:
        return False, [], None, None

    inventory = []

    for filename, text in files.items():

        if not isinstance(filename, str):
            return False, [], None, None

        if filename == "":
            return False, [], None, None

        if not isinstance(text, str):
            return False, [], None, None

        try:
            raw = text.encode("utf-8")
        except UnicodeEncodeError:
            return False, [], None, None

        inventory.append({
            "name": filename,
            "bytes": len(raw),
            "sha256": sha256_hex(raw),
        })

    inventory.sort(
        key=lambda item: item["name"].encode("utf-8")
    )

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


def recompute_inventory(inventory):
    """
    Recompute the total and package digest from a submitted inventory.

    The submitted totalBytes/packageDigest are NEVER trusted.
    """

    if not isinstance(inventory, list):
        return False, None, None

    if len(inventory) == 0:
        return False, None, None

    normalized = []
    seen = set()

    for item in inventory:

        if not isinstance(item, dict):
            return False, None, None

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

        if name in seen:
            return False, None, None

        seen.add(name)

        if not safe_nonnegative_integer(byte_count):
            return False, None, None

        if not isinstance(digest, str):
            return False, None, None

        if len(digest) != 64:
            return False, None, None

        if any(
            character not in "0123456789abcdef"
            for character in digest
        ):
            return False, None, None

        normalized.append({
            "name": name,
            "bytes": byte_count,
            "sha256": digest,
        })

    expected = sorted(
        normalized,
        key=lambda item: item["name"].encode("utf-8"),
    )

    # Inventory itself must already be sorted.
    if normalized != expected:
        return False, None, None

    total_bytes = sum(
        item["bytes"]
        for item in normalized
    )

    package_digest = sha256_hex(
        compact_json_bytes(normalized)
    )

    return (
        True,
        total_bytes,
        package_digest,
    )


# ============================================================
# FREEZE REQUEST VALIDATION
# ============================================================

def valid_freeze_request(body):
    """
    Only reject malformed top-level freeze requests.

    Candidate-level errors are deliberately handled later and become
    status="invalid".
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

    if not nonempty_string(
        body.get("calibrationDigest")
    ):
        return False

    if not nonempty_string(
        body.get("tokenizerDigest")
    ):
        return False

    allowed = body.get(
        "allowedUnsupportedReasons"
    )

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

    if not isinstance(candidates, list):
        return False

    if len(candidates) == 0:
        return False

    # DO NOT reject malformed candidate internals here.
    #
    # The candidate itself is processed by freeze_candidate()
    # and can become status="invalid".

    return True


# ============================================================
# PROCESS ONE FREEZE CANDIDATE
# ============================================================

def process_freeze_candidate(
    candidate,
    calibration_digest,
    tokenizer_digest,
    allowed_reasons,
):
    """
    Convert one submitted candidate into the exact frozen response object.
    """

    # --------------------------------------------------------
    # Candidate must be an object.
    # --------------------------------------------------------

    if not isinstance(candidate, dict):

        return {
            "name": "",
            "status": "invalid",
            "inventory": [],
            "totalBytes": None,
            "packageDigest": None,
            "reasonCodes": [
                "INVALID_INPUT"
            ],
        }

    name = candidate.get("name")

    # --------------------------------------------------------
    # Candidate name.
    # --------------------------------------------------------

    if not nonempty_string(name):

        return {
            "name": "",
            "status": "invalid",
            "inventory": [],
            "totalBytes": None,
            "packageDigest": None,
            "reasonCodes": [
                "INVALID_INPUT"
            ],
        }

    # --------------------------------------------------------
    # Files.
    # --------------------------------------------------------

    files_valid, inventory, total_bytes, package_digest = (
        build_inventory(
            candidate.get("files")
        )
    )

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

    # --------------------------------------------------------
    # Unsupported reason.
    #
    # Any unsupportedReason makes the candidate unsupported
    # only when that reason is explicitly allowed.
    # --------------------------------------------------------

    if "unsupportedReason" in candidate:

        unsupported_reason = candidate.get(
            "unsupportedReason"
        )

        if not nonempty_string(
            unsupported_reason
        ):

            return {
                "name": name,
                "status": "invalid",
                "inventory": inventory,
                "totalBytes": total_bytes,
                "packageDigest": package_digest,
                "reasonCodes": [
                    "INVALID_INPUT"
                ],
            }

        if unsupported_reason in allowed_reasons:

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
            "reasonCodes": [
                "UNALLOWED_UNSUPPORTED_REASON"
            ],
        }

    # --------------------------------------------------------
    # Normal frozen candidate.
    # --------------------------------------------------------

    if candidate.get("loadable") is not True:
        reason_codes.append(
            "NOT_LOADABLE"
        )

    if (
        candidate.get("calibrationDigest")
        != calibration_digest
    ):
        reason_codes.append(
            "CALIBRATION_MISMATCH"
        )

    if (
        candidate.get("tokenizerDigest")
        != tokenizer_digest
    ):
        reason_codes.append(
            "TOKENIZER_MISMATCH"
        )

    reason_codes = sort_codes(
        reason_codes
    )

    if len(reason_codes) > 0:
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


# ============================================================
# FREEZE
# ============================================================

def perform_freeze(body):

    freeze_id = body["freezeId"]

    current_fingerprint = request_fingerprint(
        body
    )

    with _LOCK:

        # ----------------------------------------------------
        # Existing freeze ID.
        # ----------------------------------------------------

        if freeze_id in _FREEZES:

            if (
                _FREEZE_FINGERPRINTS[freeze_id]
                == current_fingerprint
            ):
                # Identical replay.
                return _FREEZES[freeze_id]

            # Same ID, different request.
            return error_freeze_conflict()

        # ----------------------------------------------------
        # Construct response.
        # ----------------------------------------------------

        allowed_reasons = set(
            body["allowedUnsupportedReasons"]
        )

        candidates = []

        for candidate in body["candidates"]:

            result = process_freeze_candidate(
                candidate,
                body["calibrationDigest"],
                body["tokenizerDigest"],
                allowed_reasons,
            )

            candidates.append(result)

        # ----------------------------------------------------
        # Sort candidates by UTF-8 name.
        # ----------------------------------------------------

        candidates.sort(
            key=lambda item:
                item["name"].encode("utf-8")
        )

        response = {
            "freezeId": freeze_id,
            "candidates": candidates,
        }

        # ----------------------------------------------------
        # Persist only after complete successful construction.
        # ----------------------------------------------------

        _FREEZES[freeze_id] = response
        _FREEZE_FINGERPRINTS[
            freeze_id
        ] = current_fingerprint

        return response


# ============================================================
# SELECT REQUEST SHAPE
# ============================================================

def valid_select_request(body):

    if not isinstance(body, dict):
        return False

    if body.get("phase") != "select":
        return False

    # The specification explicitly requires these.
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

    if not isinstance(
        body.get("policy"),
        dict,
    ):
        return False

    return True


# ============================================================
# POLICY VALIDATION
# ============================================================

def validate_policy(
    policy,
    candidate_names,
):
    """
    Return True only when policy values can safely be evaluated.
    """

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

    max_bytes = policy["maxBytes"]

    if not safe_nonnegative_integer(
        max_bytes
    ):
        return False

    aggregate_floor = policy[
        "aggregateFloor"
    ]

    if not valid_floor(
        aggregate_floor
    ):
        return False

    required_slices = policy[
        "requiredSlices"
    ]

    if not isinstance(
        required_slices,
        dict,
    ):
        return False

    for slice_name, floor in (
        required_slices.items()
    ):

        if not nonempty_string(
            slice_name
        ):
            return False

        if not valid_floor(
            floor
        ):
            return False

    max_latency = policy[
        "maxLatencyMs"
    ]

    if not finite_nonnegative(
        max_latency
    ):
        return False

    candidate_order = policy[
        "candidateOrder"
    ]

    if not isinstance(
        candidate_order,
        list,
    ):
        return False

    if len(candidate_order) != len(
        candidate_names
    ):
        return False

    seen = set()

    for name in candidate_order:

        if not nonempty_string(name):
            return False

        if name in seen:
            return False

        seen.add(name)

    return (
        seen == candidate_names
    )


# ============================================================
# MANIFEST VALIDATION
# ============================================================

def candidate_manifest_valid(
    candidate
):
    inventory = candidate.get(
        "inventory"
    )

    valid, calculated_total, calculated_digest = (
        recompute_inventory(
            inventory
        )
    )

    if not valid:
        return False

    if (
        candidate.get("totalBytes")
        != calculated_total
    ):
        return False

    if (
        candidate.get("packageDigest")
        != calculated_digest
    ):
        return False

    return True


# ============================================================
# PREDICTION VALIDATION
# ============================================================

def prediction_valid(
    candidate_name,
    rows,
):
    """
    Check every row for the current candidate.
    """

    for row in rows:

        if not isinstance(
            row,
            dict,
        ):
            return False

        if "label" not in row:
            return False

        if "slice" not in row:
            return False

        if "predictions" not in row:
            return False

        label = row["label"]

        # Binary label.
        if (
            not isinstance(label, int)
            or isinstance(label, bool)
            or label not in (0, 1)
        ):
            return False

        slice_name = row["slice"]

        if not nonempty_string(
            slice_name
        ):
            return False

        predictions = row[
            "predictions"
        ]

        if not isinstance(
            predictions,
            dict,
        ):
            return False

        if candidate_name not in predictions:
            return False

        prediction = predictions[
            candidate_name
        ]

        if (
            not isinstance(
                prediction,
                int,
            )
            or isinstance(
                prediction,
                bool,
            )
            or prediction not in (0, 1)
        ):
            return False

    return True


# ============================================================
# EVALUATE CANDIDATE
# ============================================================

def evaluate_candidate(
    candidate,
    rows,
    policy,
    latencies,
    lineage_valid,
):
    name = candidate["name"]

    reason_codes = []

    # --------------------------------------------------------
    # Lineage.
    # --------------------------------------------------------

    if not lineage_valid:
        reason_codes.append(
            "INVALID_LINEAGE"
        )

    # --------------------------------------------------------
    # Candidate must be frozen.
    # --------------------------------------------------------

    if candidate.get("status") != "frozen":
        reason_codes.append(
            "NOT_FROZEN"
        )

    # --------------------------------------------------------
    # Manifest.
    # --------------------------------------------------------

    manifest_valid = (
        candidate_manifest_valid(
            candidate
        )
    )

    if not manifest_valid:
        reason_codes.append(
            "INVALID_MANIFEST"
        )

    # --------------------------------------------------------
    # Predictions.
    # --------------------------------------------------------

    predictions_valid = prediction_valid(
        name,
        rows,
    )

    if not predictions_valid:
        reason_codes.append(
            "INVALID_PREDICTIONS"
        )

    # --------------------------------------------------------
    # Metrics.
    # --------------------------------------------------------

    aggregate = None
    slices = {}

    if (
        predictions_valid
        and len(rows) > 0
    ):

        correct = 0

        slice_total = {}
        slice_correct = {}

        for row in rows:

            label = row["label"]
            slice_name = row["slice"]
            prediction = row[
                "predictions"
            ][name]

            slice_total[
                slice_name
            ] = (
                slice_total.get(
                    slice_name,
                    0,
                )
                + 1
            )

            if prediction == label:

                correct += 1

                slice_correct[
                    slice_name
                ] = (
                    slice_correct.get(
                        slice_name,
                        0,
                    )
                    + 1
                )

        aggregate = round12(
            correct / len(rows)
        )

        for slice_name in (
            policy["requiredSlices"]
        ):

            if slice_name in slice_total:

                slices[slice_name] = round12(
                    slice_correct.get(
                        slice_name,
                        0,
                    )
                    / slice_total[
                        slice_name
                    ]
                )

            else:
                slices[slice_name] = None

    else:

        for slice_name in (
            policy["requiredSlices"]
        ):
            slices[slice_name] = None

    # --------------------------------------------------------
    # Aggregate floor.
    # --------------------------------------------------------

    if predictions_valid:

        if (
            aggregate is None
            or aggregate
            < float(
                policy[
                    "aggregateFloor"
                ]
            )
        ):
            reason_codes.append(
                "AGGREGATE_FLOOR"
            )

        # ----------------------------------------------------
        # Required slices.
        # ----------------------------------------------------

        for (
            slice_name,
            floor,
        ) in policy[
            "requiredSlices"
        ].items():

            value = slices.get(
                slice_name
            )

            if value is None:

                reason_codes.append(
                    "MISSING_SLICE:"
                    + slice_name
                )

            elif value < float(
                floor
            ):

                reason_codes.append(
                    "SLICE_FLOOR:"
                    + slice_name
                )

    # --------------------------------------------------------
    # Size.
    # --------------------------------------------------------

    total_bytes = None

    if (
        manifest_valid
        and safe_nonnegative_integer(
            candidate.get(
                "totalBytes"
            )
        )
    ):

        total_bytes = candidate[
            "totalBytes"
        ]

        if (
            total_bytes
            > policy["maxBytes"]
        ):
            reason_codes.append(
                "SIZE_LIMIT"
            )

    # If manifest cannot be validated, totalBytes must be null.
    else:
        total_bytes = None

    # --------------------------------------------------------
    # Latency.
    # --------------------------------------------------------

    latency_ms = None

    if (
        isinstance(
            latencies,
            dict,
        )
        and name in latencies
    ):

        latency = latencies[name]

        if finite_nonnegative(
            latency
        ):

            latency_ms = latency

            if (
                float(latency)
                > float(
                    policy[
                        "maxLatencyMs"
                    ]
                )
            ):
                reason_codes.append(
                    "LATENCY_LIMIT"
                )

    # --------------------------------------------------------
    # Deterministic reason codes.
    # --------------------------------------------------------

    reason_codes = sort_codes(
        reason_codes
    )

    admitted = (
        len(reason_codes) == 0
    )

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
# SELECT
# ============================================================

def perform_select(body):

    freeze_id = body.get(
        "freezeId"
    )

    with _LOCK:
        frozen_response = _FREEZES.get(
            freeze_id
        )

    # --------------------------------------------------------
    # Unknown freeze.
    # --------------------------------------------------------

    if frozen_response is None:

        names = []

        for candidate in body[
            "candidates"
        ]:

            if not isinstance(
                candidate,
                dict,
            ):
                continue

            name = candidate.get(
                "name"
            )

            if (
                nonempty_string(name)
                and name not in names
            ):
                names.append(name)

        names.sort(
            key=utf8_key
        )

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
                    "reasonCodes": [
                        "NOT_FROZEN"
                    ],
                }
                for name in names
            ],
            "packageManifest": None,
        }

    # --------------------------------------------------------
    # Frozen candidate response.
    # --------------------------------------------------------

    stored_candidates = (
        frozen_response[
            "candidates"
        ]
    )

    submitted_candidates = body[
        "candidates"
    ]

    stored_names = {
        candidate["name"]
        for candidate
        in stored_candidates
    }

    # --------------------------------------------------------
    # Exact candidate array equality.
    # --------------------------------------------------------

    lineage_valid = (
        submitted_candidates
        == stored_candidates
    )

    # --------------------------------------------------------
    # Policy.
    # --------------------------------------------------------

    policy = body[
        "policy"
    ]

    policy_valid = validate_policy(
        policy,
        stored_names,
    )

    # --------------------------------------------------------
    # Candidate lookup.
    # --------------------------------------------------------

    stored_by_name = {
        candidate["name"]: candidate
        for candidate
        in stored_candidates
    }

    submitted_by_name = {}

    for candidate in submitted_candidates:

        if not isinstance(
            candidate,
            dict,
        ):
            continue

        name = candidate.get(
            "name"
        )

        if nonempty_string(name):
            submitted_by_name[
                name
            ] = candidate

    # --------------------------------------------------------
    # Result order.
    # --------------------------------------------------------

    names = list(
        stored_names
    )

    if policy_valid:

        order_index = {
            name: index
            for index, name
            in enumerate(
                policy[
                    "candidateOrder"
                ]
            )
        }

        names.sort(
            key=lambda name: (
                order_index.get(
                    name,
                    len(order_index),
                ),
                name.encode("utf-8"),
            )
        )

    else:

        names.sort(
            key=utf8_key
        )

    # --------------------------------------------------------
    # Evaluate candidates.
    # --------------------------------------------------------

    results = []

    for name in names:

        candidate = submitted_by_name.get(
            name
        )

        if candidate is None:
            candidate = stored_by_name[
                name
            ]

        # ----------------------------------------------------
        # Invalid policy.
        # ----------------------------------------------------

        if not policy_valid:

            codes = [
                "INVALID_POLICY"
            ]

            if not lineage_valid:
                codes.append(
                    "INVALID_LINEAGE"
                )

            results.append({
                "name": name,
                "aggregate": None,
                "slices": {},
                "totalBytes": None,
                "latencyMs": None,
                "admitted": False,
                "reasonCodes": sort_codes(
                    codes
                ),
            })

            continue

        result = evaluate_candidate(
            candidate,
            body["rows"],
            policy,
            body.get(
                "latencies",
                {},
            ),
            lineage_valid,
        )

        results.append(
            result
        )

    # --------------------------------------------------------
    # Select winner.
    #
    # Smaller bytes
    # then lower latency
    # then candidate order
    # then UTF-8 name fallback
    # --------------------------------------------------------

    selected = None

    if policy_valid:

        order_index = {
            name: index
            for index, name
            in enumerate(
                policy[
                    "candidateOrder"
                ]
            )
        }

        admitted = [
            result
            for result in results
            if result[
                "admitted"
            ]
        ]

        admitted.sort(
            key=lambda result: (
                result[
                    "totalBytes"
                ],
                float(
                    result[
                        "latencyMs"
                    ]
                ),
                order_index.get(
                    result[
                        "name"
                    ],
                    len(order_index),
                ),
                result[
                    "name"
                ].encode("utf-8"),
            )
        )

        if admitted:
            selected = admitted[
                0
            ]["name"]

    # --------------------------------------------------------
    # Winner manifest.
    # --------------------------------------------------------

    package_manifest = None

    if selected is not None:

        package_manifest = (
            stored_by_name[
                selected
            ]
        )

    return {
        "freezeId": freeze_id,
        "selected": selected,
        "results": results,
        "packageManifest": package_manifest,
    }


# ============================================================
# POST /quantize
# ============================================================

@app.post("/quantize")
async def quantize(request: Request):

    try:
        body = await request.json()
    except Exception:
        return error_invalid_input()

    if not isinstance(body, dict):
        return error_invalid_input()

    phase = body.get(
        "phase"
    )

    # --------------------------------------------------------
    # FREEZE
    # --------------------------------------------------------

    if phase == "freeze":

        if not valid_freeze_request(
            body
        ):
            return error_invalid_input()

        result = perform_freeze(
            body
        )

        if isinstance(
            result,
            JSONResponse,
        ):
            return result

        return JSONResponse(
            status_code=200,
            content=result,
        )

    # --------------------------------------------------------
    # SELECT
    # --------------------------------------------------------

    if phase == "select":

        if not valid_select_request(
            body
        ):
            return error_invalid_input()

        result = perform_select(
            body
        )

        return JSONResponse(
            status_code=200,
            content=result,
        )

    # --------------------------------------------------------
    # Unknown/missing phase.
    # --------------------------------------------------------

    return error_invalid_input()


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/")
def root():
    return {
        "ok": True
    }
