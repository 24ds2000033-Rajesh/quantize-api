from __future__ import annotations

import hashlib
import json
import math
import threading
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

# Stateful in-process storage
FREEZES: dict[str, dict[str, Any]] = {}
FREEZE_INPUTS: dict[str, str] = {}
LOCK = threading.RLock()

MAX_SAFE = 9007199254740991


# ============================================================
# BASIC HELPERS
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


def nonempty_string(x):
    return isinstance(x, str) and len(x) > 0


def utf8_key(x):
    return x.encode("utf-8")


def codes_sorted(codes):
    return sorted(set(codes), key=utf8_key)


def compact_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def safe_integer(x):
    return (
        isinstance(x, int)
        and not isinstance(x, bool)
        and 0 <= x <= MAX_SAFE
    )


def finite_nonnegative(x):
    return (
        isinstance(x, (int, float))
        and not isinstance(x, bool)
        and math.isfinite(float(x))
        and float(x) >= 0
    )


def valid_floor(x):
    return (
        isinstance(x, (int, float))
        and not isinstance(x, bool)
        and math.isfinite(float(x))
        and 0 <= float(x) <= 1
    )


def fingerprint(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


# ============================================================
# FILE INVENTORY
# ============================================================

def make_inventory(files):

    if not isinstance(files, dict):
        return False, [], None, None

    if len(files) == 0:
        return False, [], None, None

    inventory = []

    for filename, content in files.items():

        if not isinstance(filename, str):
            return False, [], None, None

        if filename == "":
            return False, [], None, None

        if not isinstance(content, str):
            return False, [], None, None

        try:
            raw = content.encode("utf-8")
        except Exception:
            return False, [], None, None

        inventory.append({
            "name": filename,
            "bytes": len(raw),
            "sha256": sha256(raw),
        })

    inventory.sort(
        key=lambda x: x["name"].encode("utf-8")
    )

    total = sum(
        x["bytes"] for x in inventory
    )

    package_digest = sha256(
        compact_json(inventory)
    )

    return True, inventory, total, package_digest


def verify_inventory(inventory):

    if not isinstance(inventory, list):
        return False, None, None

    if len(inventory) == 0:
        return False, None, None

    seen = set()
    normalized = []

    for item in inventory:

        if not isinstance(item, dict):
            return False, None, None

        if set(item.keys()) != {
            "name",
            "bytes",
            "sha256",
        }:
            return False, None, None

        name = item["name"]
        byte_count = item["bytes"]
        digest = item["sha256"]

        if not nonempty_string(name):
            return False, None, None

        if name in seen:
            return False, None, None

        seen.add(name)

        if not safe_integer(byte_count):
            return False, None, None

        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(
                c not in "0123456789abcdef"
                for c in digest
            )
        ):
            return False, None, None

        normalized.append({
            "name": name,
            "bytes": byte_count,
            "sha256": digest,
        })

    expected = sorted(
        normalized,
        key=lambda x: x["name"].encode("utf-8"),
    )

    if normalized != expected:
        return False, None, None

    total = sum(
        x["bytes"] for x in normalized
    )

    package = sha256(
        compact_json(normalized)
    )

    return True, total, package


# ============================================================
# FREEZE TOP-LEVEL VALIDATION
# ============================================================

def freeze_request_valid(body):

    if not isinstance(body, dict):
        print("FREEZE INVALID: body_not_object", flush=True)
        return False

    if body.get("phase") != "freeze":
        print("FREEZE INVALID: phase", body.get("phase"), flush=True)
        return False

    freeze_id = body.get("freezeId")

    if not nonempty_string(freeze_id):
        print("FREEZE INVALID: freezeId", repr(freeze_id), flush=True)
        return False

    if len(freeze_id) > 128:
        print("FREEZE INVALID: freezeId_too_long", flush=True)
        return False

    calibration = body.get("calibrationDigest")

    if not nonempty_string(calibration):
        print(
            "FREEZE INVALID: calibrationDigest",
            repr(calibration),
            flush=True,
        )
        return False

    tokenizer = body.get("tokenizerDigest")

    if not nonempty_string(tokenizer):
        print(
            "FREEZE INVALID: tokenizerDigest",
            repr(tokenizer),
            flush=True,
        )
        return False

    allowed = body.get(
        "allowedUnsupportedReasons"
    )

    if not isinstance(allowed, list):
        print(
            "FREEZE INVALID: allowedUnsupportedReasons_type",
            type(allowed).__name__,
            flush=True,
        )
        return False

    seen = set()

    for reason in allowed:

        if not nonempty_string(reason):
            print(
                "FREEZE INVALID: empty_allowed_reason",
                repr(reason),
                flush=True,
            )
            return False

        if reason in seen:
            print(
                "FREEZE INVALID: duplicate_allowed_reason",
                repr(reason),
                flush=True,
            )
            return False

        seen.add(reason)

    candidates = body.get("candidates")

    if not isinstance(candidates, list):
        print(
            "FREEZE INVALID: candidates_not_array",
            type(candidates).__name__,
            flush=True,
        )
        return False

    if len(candidates) == 0:
        print(
            "FREEZE INVALID: candidates_empty",
            flush=True,
        )
        return False

    # Candidate internals are deliberately NOT rejected here.
    # They are converted into invalid candidates below.

    return True


# ============================================================
# FREEZE CANDIDATE
# ============================================================

def freeze_candidate(
    candidate,
    calibration_digest,
    tokenizer_digest,
    allowed,
):

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

    files = candidate.get("files")

    valid, inventory, total, package = make_inventory(
        files
    )

    if not valid:
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

    # --------------------------------------------------------
    # unsupportedReason
    # --------------------------------------------------------

    if "unsupportedReason" in candidate:

        reason = candidate.get(
            "unsupportedReason"
        )

        if not nonempty_string(reason):
            return {
                "name": name,
                "status": "invalid",
                "inventory": inventory,
                "totalBytes": total,
                "packageDigest": package,
                "reasonCodes": [
                    "INVALID_INPUT"
                ],
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

    # --------------------------------------------------------
    # Normal candidate
    # --------------------------------------------------------

    reasons = []

    if candidate.get("loadable") is not True:
        reasons.append(
            "NOT_LOADABLE"
        )

    if (
        candidate.get("calibrationDigest")
        != calibration_digest
    ):
        reasons.append(
            "CALIBRATION_MISMATCH"
        )

    if (
        candidate.get("tokenizerDigest")
        != tokenizer_digest
    ):
        reasons.append(
            "TOKENIZER_MISMATCH"
        )

    reasons = codes_sorted(reasons)

    return {
        "name": name,
        "status": (
            "invalid"
            if reasons
            else "frozen"
        ),
        "inventory": inventory,
        "totalBytes": total,
        "packageDigest": package,
        "reasonCodes": reasons,
    }


# ============================================================
# FREEZE
# ============================================================

def do_freeze(body):

    freeze_id = body["freezeId"]

    fp = fingerprint(body)

    with LOCK:

        if freeze_id in FREEZES:

            if (
                FREEZE_INPUTS[freeze_id]
                == fp
            ):
                return FREEZES[freeze_id]

            return conflict()

        allowed = set(
            body["allowedUnsupportedReasons"]
        )

        output = []

        for candidate in body[
            "candidates"
        ]:

            output.append(
                freeze_candidate(
                    candidate,
                    body["calibrationDigest"],
                    body["tokenizerDigest"],
                    allowed,
                )
            )

        output.sort(
            key=lambda x:
                x["name"].encode("utf-8")
        )

        response = {
            "freezeId": freeze_id,
            "candidates": output,
        }

        FREEZES[freeze_id] = response
        FREEZE_INPUTS[freeze_id] = fp

        return response


# ============================================================
# SELECT TOP-LEVEL VALIDATION
# ============================================================

def select_request_valid(body):

    if not isinstance(body, dict):
        print(
            "SELECT INVALID: body_not_object",
            flush=True,
        )
        return False

    if body.get("phase") != "select":
        print(
            "SELECT INVALID: phase",
            repr(body.get("phase")),
            flush=True,
        )
        return False

    if not isinstance(
        body.get("candidates"),
        list,
    ):
        print(
            "SELECT INVALID: candidates",
            flush=True,
        )
        return False

    if not isinstance(
        body.get("rows"),
        list,
    ):
        print(
            "SELECT INVALID: rows",
            flush=True,
        )
        return False

    if not isinstance(
        body.get("policy"),
        dict,
    ):
        print(
            "SELECT INVALID: policy",
            flush=True,
        )
        return False

    return True


# ============================================================
# POLICY
# ============================================================

def valid_policy(
    policy,
    candidate_names,
):

    if not isinstance(policy, dict):
        return False

    required = [
        "maxBytes",
        "aggregateFloor",
        "requiredSlices",
        "maxLatencyMs",
        "candidateOrder",
    ]

    for field in required:
        if field not in policy:
            return False

    if not safe_integer(
        policy["maxBytes"]
    ):
        return False

    if not valid_floor(
        policy["aggregateFloor"]
    ):
        return False

    slices = policy[
        "requiredSlices"
    ]

    if not isinstance(slices, dict):
        return False

    for name, floor in slices.items():

        if not nonempty_string(name):
            return False

        if not valid_floor(floor):
            return False

    if not finite_nonnegative(
        policy["maxLatencyMs"]
    ):
        return False

    order = policy[
        "candidateOrder"
    ]

    if not isinstance(order, list):
        return False

    if len(order) != len(
        candidate_names
    ):
        return False

    seen = set()

    for name in order:

        if not nonempty_string(name):
            return False

        if name in seen:
            return False

        seen.add(name)

    return (
        seen == candidate_names
    )


# ============================================================
# MANIFEST
# ============================================================

def manifest_valid(candidate):

    valid, total, package = verify_inventory(
        candidate.get("inventory")
    )

    if not valid:
        return False

    if candidate.get(
        "totalBytes"
    ) != total:
        return False

    if candidate.get(
        "packageDigest"
    ) != package:
        return False

    return True


# ============================================================
# PREDICTIONS
# ============================================================

def predictions_valid(
    name,
    rows,
):

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

        if (
            not isinstance(label, int)
            or isinstance(label, bool)
            or label not in (0, 1)
        ):
            return False

        if not nonempty_string(
            row["slice"]
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

        if name not in predictions:
            return False

        prediction = predictions[
            name
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
# EVALUATE
# ============================================================

def evaluate(
    candidate,
    rows,
    policy,
    latencies,
    lineage_valid,
):

    name = candidate["name"]

    reasons = []

    if not lineage_valid:
        reasons.append(
            "INVALID_LINEAGE"
        )

    if candidate.get(
        "status"
    ) != "frozen":
        reasons.append(
            "NOT_FROZEN"
        )

    manifest_ok = manifest_valid(
        candidate
    )

    if not manifest_ok:
        reasons.append(
            "INVALID_MANIFEST"
        )

    prediction_ok = predictions_valid(
        name,
        rows,
    )

    if not prediction_ok:
        reasons.append(
            "INVALID_PREDICTIONS"
        )

    aggregate = None
    slices = {}

    if (
        prediction_ok
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
            ] = slice_total.get(
                slice_name,
                0,
            ) + 1

            if prediction == label:

                correct += 1

                slice_correct[
                    slice_name
                ] = slice_correct.get(
                    slice_name,
                    0,
                ) + 1

        aggregate = round12(
            correct / len(rows)
        )

        for slice_name in (
            policy[
                "requiredSlices"
            ]
        ):

            if (
                slice_name
                in slice_total
            ):

                slices[
                    slice_name
                ] = round12(
                    slice_correct.get(
                        slice_name,
                        0,
                    )
                    / slice_total[
                        slice_name
                    ]
                )

            else:
                slices[
                    slice_name
                ] = None

    else:

        for slice_name in (
            policy[
                "requiredSlices"
            ]
        ):
            slices[
                slice_name
            ] = None

    # Aggregate floor
    if prediction_ok:

        if (
            aggregate is None
            or aggregate
            < float(
                policy[
                    "aggregateFloor"
                ]
            )
        ):
            reasons.append(
                "AGGREGATE_FLOOR"
            )

        # Required slices
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

                reasons.append(
                    "MISSING_SLICE:"
                    + slice_name
                )

            elif value < float(floor):

                reasons.append(
                    "SLICE_FLOOR:"
                    + slice_name
                )

    # Size
    total_bytes = None

    if manifest_ok:

        total_bytes = candidate[
            "totalBytes"
        ]

        if (
            total_bytes
            > policy["maxBytes"]
        ):
            reasons.append(
                "SIZE_LIMIT"
            )

    # Latency
    latency_ms = None

    if (
        isinstance(
            latencies,
            dict,
        )
        and name in latencies
    ):

        value = latencies[name]

        if finite_nonnegative(value):

            latency_ms = value

            if (
                float(value)
                > float(
                    policy[
                        "maxLatencyMs"
                    ]
                )
            ):
                reasons.append(
                    "LATENCY_LIMIT"
                )

    reasons = codes_sorted(
        reasons
    )

    return {
        "name": name,
        "aggregate": aggregate,
        "slices": slices,
        "totalBytes": total_bytes,
        "latencyMs": latency_ms,
        "admitted": len(reasons) == 0,
        "reasonCodes": reasons,
    }


# ============================================================
# SELECT
# ============================================================

def do_select(body):

    freeze_id = body.get(
        "freezeId"
    )

    with LOCK:
        frozen = FREEZES.get(
            freeze_id
        )

    # --------------------------------------------------------
    # Not frozen
    # --------------------------------------------------------

    if frozen is None:

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

    stored = frozen[
        "candidates"
    ]

    supplied = body[
        "candidates"
    ]

    stored_names = {
        c["name"]
        for c in stored
    }

    # Exact supplied candidate array
    lineage_valid = (
        supplied == stored
    )

    policy = body[
        "policy"
    ]

    policy_valid = valid_policy(
        policy,
        stored_names,
    )

    stored_by_name = {
        c["name"]: c
        for c in stored
    }

    supplied_by_name = {}

    for c in supplied:

        if not isinstance(c, dict):
            continue

        name = c.get("name")

        if nonempty_string(name):
            supplied_by_name[
                name
            ] = c

    # Result order
    names = list(
        stored_names
    )

    if policy_valid:

        order_index = {
            name: index
            for index, name in enumerate(
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

    results = []

    for name in names:

        candidate = supplied_by_name.get(
            name
        )

        if candidate is None:
            candidate = stored_by_name[
                name
            ]

        if not policy_valid:

            reasons = [
                "INVALID_POLICY"
            ]

            if not lineage_valid:
                reasons.append(
                    "INVALID_LINEAGE"
                )

            results.append({
                "name": name,
                "aggregate": None,
                "slices": {},
                "totalBytes": None,
                "latencyMs": None,
                "admitted": False,
                "reasonCodes": codes_sorted(
                    reasons
                ),
            })

            continue

        results.append(
            evaluate(
                candidate,
                body["rows"],
                policy,
                body.get(
                    "latencies",
                    {},
                ),
                lineage_valid,
            )
        )

    # --------------------------------------------------------
    # Winner
    # --------------------------------------------------------

    selected = None

    if policy_valid:

        order_index = {
            name: index
            for index, name in enumerate(
                policy[
                    "candidateOrder"
                ]
            )
        }

        winners = [
            result
            for result in results
            if result[
                "admitted"
            ]
        ]

        winners.sort(
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

        if winners:
            selected = winners[
                0
            ]["name"]

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
# ENDPOINT
# ============================================================

@app.post("/quantize")
async def quantize(request: Request):

    try:
        body = await request.json()
    except Exception as exc:
        print(
            "JSON PARSE ERROR:",
            repr(exc),
            flush=True,
        )
        return invalid_input()

    print(
        "QUANTIZE REQUEST PHASE:",
        repr(
            body.get("phase")
            if isinstance(body, dict)
            else None
        ),
        flush=True,
    )

    if not isinstance(body, dict):
        return invalid_input()

    phase = body.get(
        "phase"
    )

    # --------------------------------------------------------
    # FREEZE
    # --------------------------------------------------------

    if phase == "freeze":

        if not freeze_request_valid(
            body
        ):
            return invalid_input()

        result = do_freeze(
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

        if not select_request_valid(
            body
        ):
            return invalid_input()

        return JSONResponse(
            status_code=200,
            content=do_select(
                body
            ),
        )

    # --------------------------------------------------------
    # Unknown/missing phase
    # --------------------------------------------------------

    print(
        "QUANTIZE INVALID PHASE:",
        repr(phase),
        flush=True,
    )

    return invalid_input()


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():
    return {"ok": True}
