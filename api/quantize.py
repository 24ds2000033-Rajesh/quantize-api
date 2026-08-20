import hashlib
import json
import math
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


app = FastAPI()

# Stateful freeze records.
FREEZES = {}


# ============================================================
# JSON / HASH / UTF-8
# ============================================================

def compact_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utf8_key(value: str) -> bytes:
    return value.encode("utf-8")


# ============================================================
# BASIC VALIDATION
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

    if any(
        not is_nonempty_string(x)
        for x in value
    ):
        return False

    return len(value) == len(set(value))


def add_code(codes, code):
    if code not in codes:
        codes.append(code)


def sort_codes(codes):
    return sorted(
        set(codes),
        key=utf8_key,
    )


# ============================================================
# FREEZE REQUEST SHAPE
# ============================================================

def validate_freeze_shape(body):
    """
    Only the explicitly specified malformed top-level requests
    are rejected with HTTP 400.

    Duplicate candidate names are handled separately.
    """

    if not isinstance(body, dict):
        return False, "body_not_object"

    if body.get("phase") != "freeze":
        return False, "bad_phase"

    freeze_id = body.get("freezeId")

    if not is_nonempty_string(freeze_id):
        return False, "bad_freezeId"

    if len(freeze_id) > 128:
        return False, "freezeId_too_long"

    if not is_nonempty_string(
        body.get("calibrationDigest")
    ):
        return False, "bad_calibrationDigest"

    if not is_nonempty_string(
        body.get("tokenizerDigest")
    ):
        return False, "bad_tokenizerDigest"

    allowed = body.get(
        "allowedUnsupportedReasons"
    )

    if not unique_nonempty_strings(
        allowed,
        allow_empty=True,
    ):
        return False, "bad_allowedUnsupportedReasons"

    candidates = body.get(
        "candidates"
    )

    if not isinstance(
        candidates,
        list,
    ):
        return False, "candidates_not_array"

    if len(candidates) == 0:
        return False, "candidates_empty"

    for index, candidate in enumerate(
        candidates
    ):
        if not isinstance(
            candidate,
            dict,
        ):
            return (
                False,
                f"candidate_{index}_not_object",
            )

        if not is_nonempty_string(
            candidate.get("name")
        ):
            return (
                False,
                f"candidate_{index}_bad_name",
            )

    return True, None


# ============================================================
# FILE INVENTORY
# ============================================================

def build_inventory(candidate):
    files = candidate.get("files")

    if not isinstance(files, dict):
        return False, [], None, None

    if len(files) == 0:
        return False, [], None, None

    for filename, content in files.items():

        if not isinstance(
            filename,
            str,
        ):
            return False, [], None, None

        if filename == "":
            return False, [], None, None

        if not isinstance(
            content,
            str,
        ):
            return False, [], None, None

    inventory = []

    for filename in sorted(
        files.keys(),
        key=utf8_key,
    ):
        raw = files[
            filename
        ].encode("utf-8")

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
        compact_json_bytes(
            inventory
        )
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
    calibration_digest,
    tokenizer_digest,
    allowed_reasons,
    duplicate_name=False,
):
    name = candidate.get("name")

    # Duplicate candidate names make the candidate invalid.
    if duplicate_name:

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

    files_ok, inventory, total_bytes, package_digest = (
        build_inventory(candidate)
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

    reason_codes = []

    status = "frozen"

    unsupported_reason = candidate.get(
        "unsupportedReason"
    )

    # --------------------------------------------------------
    # Unsupported
    # --------------------------------------------------------

    if (
        isinstance(
            unsupported_reason,
            str,
        )
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

        if candidate.get(
            "loadable"
        ) is not True:

            status = "invalid"

            add_code(
                reason_codes,
                "NOT_LOADABLE",
            )

        if (
            candidate.get(
                "calibrationDigest"
            )
            != calibration_digest
        ):

            status = "invalid"

            add_code(
                reason_codes,
                "CALIBRATION_MISMATCH",
            )

        if (
            candidate.get(
                "tokenizerDigest"
            )
            != tokenizer_digest
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
        "reasonCodes": sort_codes(
            reason_codes
        ),
    }


# ============================================================
# CREATE FREEZE
# ============================================================

def create_freeze_response(body):

    candidates_input = body[
        "candidates"
    ]

    # Detect duplicate names.
    name_counts = {}

    for candidate in candidates_input:

        name = candidate.get(
            "name"
        )

        name_counts[name] = (
            name_counts.get(
                name,
                0,
            )
            + 1
        )

    duplicate_names = {
        name
        for name, count
        in name_counts.items()
        if count > 1
    }

    allowed_reasons = set(
        body[
            "allowedUnsupportedReasons"
        ]
    )

    output = []

    for candidate in candidates_input:

        name = candidate[
            "name"
        ]

        output.append(
            freeze_candidate(
                candidate=candidate,
                calibration_digest=body[
                    "calibrationDigest"
                ],
                tokenizer_digest=body[
                    "tokenizerDigest"
                ],
                allowed_reasons=allowed_reasons,
                duplicate_name=(
                    name in duplicate_names
                ),
            )
        )

    output.sort(
        key=lambda x: utf8_key(
            x["name"]
        )
    )

    return {
        "freezeId": body[
            "freezeId"
        ],
        "candidates": output,
    }


# ============================================================
# MANIFEST VERIFICATION
# ============================================================

def verify_manifest(candidate):

    inventory = candidate.get(
        "inventory"
    )

    if not isinstance(
        inventory,
        list,
    ):
        return False, None, None

    rebuilt = []

    names = set()

    previous_name = None

    for item in inventory:

        if not isinstance(
            item,
            dict,
        ):
            return False, None, None

        if set(item.keys()) != {
            "name",
            "bytes",
            "sha256",
        }:
            return False, None, None

        name = item.get(
            "name"
        )

        byte_count = item.get(
            "bytes"
        )

        digest = item.get(
            "sha256"
        )

        if not is_nonempty_string(
            name
        ):
            return False, None, None

        if not is_safe_nonnegative_integer(
            byte_count
        ):
            return False, None, None

        if (
            not isinstance(
                digest,
                str,
            )
            or len(digest) != 64
            or digest != digest.lower()
            or any(
                c not in
                "0123456789abcdef"
                for c in digest
            )
        ):
            return False, None, None

        if name in names:
            return False, None, None

        names.add(name)

        if previous_name is not None:

            if utf8_key(name) <= utf8_key(
                previous_name
            ):
                return False, None, None

        previous_name = name

        rebuilt.append({
            "name": name,
            "bytes": byte_count,
            "sha256": digest,
        })

    total_bytes = sum(
        x["bytes"]
        for x in rebuilt
    )

    package_digest = sha256_hex(
        compact_json_bytes(
            rebuilt
        )
    )

    if candidate.get(
        "totalBytes"
    ) != total_bytes:
        return False, None, None

    if candidate.get(
        "packageDigest"
    ) != package_digest:
        return False, None, None

    return (
        True,
        total_bytes,
        package_digest,
    )


# ============================================================
# POLICY
# ============================================================

def validate_policy(policy):

    if not isinstance(
        policy,
        dict,
    ):
        return False

    if not is_safe_nonnegative_integer(
        policy.get(
            "maxBytes"
        )
    ):
        return False

    floor = policy.get(
        "aggregateFloor"
    )

    if not is_finite_number(
        floor
    ):
        return False

    if not 0 <= float(floor) <= 1:
        return False

    required = policy.get(
        "requiredSlices"
    )

    if not isinstance(
        required,
        dict,
    ):
        return False

    for name, value in required.items():

        if not is_nonempty_string(
            name
        ):
            return False

        if not is_finite_number(
            value
        ):
            return False

        if not 0 <= float(value) <= 1:
            return False

    max_latency = policy.get(
        "maxLatencyMs"
    )

    if not is_finite_number(
        max_latency
    ):
        return False

    if float(max_latency) < 0:
        return False

    order = policy.get(
        "candidateOrder"
    )

    if not unique_nonempty_strings(
        order,
        allow_empty=False,
    ):
        return False

    return True


# ============================================================
# ACCURACY
# ============================================================

def rounded_accuracy(
    correct,
    total,
):
    if total == 0:
        return None

    return float(
        f"{correct / total:.12f}"
    )


# ============================================================
# EVALUATE CANDIDATE
# ============================================================

def evaluate_candidate(
    candidate,
    rows,
    policy,
    latencies,
):
    name = candidate[
        "name"
    ]

    codes = []

    aggregate = None

    slices = {}

    total_bytes = None

    latency_ms = None

    # --------------------------------------------------------
    # Lineage
    # --------------------------------------------------------

    if candidate.get(
        "status"
    ) != "frozen":

        add_code(
            codes,
            "INVALID_LINEAGE",
        )

    # --------------------------------------------------------
    # Manifest
    # --------------------------------------------------------

    manifest_ok, manifest_bytes, _ = (
        verify_manifest(
            candidate
        )
    )

    if manifest_ok:

        total_bytes = manifest_bytes

    else:

        add_code(
            codes,
            "INVALID_MANIFEST",
        )

    # --------------------------------------------------------
    # Predictions
    # --------------------------------------------------------

    predictions_valid = True

    aggregate_correct = 0

    slice_total = {}

    slice_correct = {}

    for row in rows:

        if not isinstance(
            row,
            dict,
        ):
            predictions_valid = False
            break

        if "label" not in row:
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

        label = row[
            "label"
        ]

        prediction = predictions[
            name
        ]

        # Binary labels.
        if (
            isinstance(
                label,
                bool,
            )
            or not isinstance(
                label,
                int,
            )
            or label not in (0, 1)
        ):
            predictions_valid = False
            break

        # Binary predictions.
        if (
            isinstance(
                prediction,
                bool,
            )
            or not isinstance(
                prediction,
                int,
            )
            or prediction not in (0, 1)
        ):
            predictions_valid = False
            break

        slice_name = row[
            "slice"
        ]

        slice_total[
            slice_name
        ] = slice_total.get(
            slice_name,
            0,
        ) + 1

        slice_correct.setdefault(
            slice_name,
            0,
        )

        if prediction == label:

            aggregate_correct += 1

            slice_correct[
                slice_name
            ] += 1

    if not predictions_valid:

        add_code(
            codes,
            "INVALID_PREDICTIONS",
        )

        aggregate = None

        for slice_name in policy[
            "requiredSlices"
        ]:
            slices[
                slice_name
            ] = None

    else:

        aggregate = rounded_accuracy(
            aggregate_correct,
            len(rows),
        )

        for slice_name in sorted(
            slice_total.keys(),
            key=utf8_key,
        ):

            slices[
                slice_name
            ] = rounded_accuracy(
                slice_correct[
                    slice_name
                ],
                slice_total[
                    slice_name
                ],
            )

        if (
            aggregate is None
            or aggregate
            < float(
                policy[
                    "aggregateFloor"
                ]
            )
        ):

            add_code(
                codes,
                "AGGREGATE_FLOOR",
            )

        for (
            slice_name,
            floor,
        ) in policy[
            "requiredSlices"
        ].items():

            if slice_name not in slice_total:

                slices[
                    slice_name
                ] = None

                add_code(
                    codes,
                    f"MISSING_SLICE:{slice_name}",
                )

            elif (
                slices[
                    slice_name
                ]
                < float(floor)
            ):

                add_code(
                    codes,
                    f"SLICE_FLOOR:{slice_name}",
                )

    # --------------------------------------------------------
    # Size
    # --------------------------------------------------------

    if total_bytes is not None:

        if (
            total_bytes
            > policy[
                "maxBytes"
            ]
        ):

            add_code(
                codes,
                "SIZE_LIMIT",
            )

    # --------------------------------------------------------
    # Latency
    # --------------------------------------------------------

    if name not in latencies:

        latency_ms = None

        add_code(
            codes,
            "LATENCY_LIMIT",
        )

    else:

        value = latencies[
            name
        ]

        if (
            is_finite_number(value)
            and float(value) >= 0
        ):

            latency_ms = value

            if (
                float(value)
                > float(
                    policy[
                        "maxLatencyMs"
                    ]
                )
            ):

                add_code(
                    codes,
                    "LATENCY_LIMIT",
                )

        else:

            latency_ms = None

            add_code(
                codes,
                "LATENCY_LIMIT",
            )

    codes = sort_codes(codes)

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
# SELECT SHAPE
# ============================================================

def validate_select_shape(body):

    if not isinstance(
        body,
        dict,
    ):
        return False

    if body.get(
        "phase"
    ) != "select":
        return False

    if not is_nonempty_string(
        body.get(
            "freezeId"
        )
    ):
        return False

    if not isinstance(
        body.get(
            "candidates"
        ),
        list,
    ):
        return False

    if not isinstance(
        body.get(
            "rows"
        ),
        list,
    ):
        return False

    if not isinstance(
        body.get(
            "policy"
        ),
        dict,
    ):
        return False

    if not isinstance(
        body.get(
            "latencies"
        ),
        dict,
    ):
        return False

    return True


# ============================================================
# SELECT
# ============================================================

def create_select_response(
    body,
    frozen,
):

    freeze_id = body[
        "freezeId"
    ]

    candidates = body[
        "candidates"
    ]

    # --------------------------------------------------------
    # Exact frozen candidate array.
    # --------------------------------------------------------

    if compact_json_bytes(
        candidates
    ) != compact_json_bytes(
        frozen[
            "candidates"
        ]
    ):

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None,
        }

    policy = body[
        "policy"
    ]

    if not validate_policy(
        policy
    ):

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None,
        }

    names = [
        c["name"]
        for c in candidates
    ]

    order = policy[
        "candidateOrder"
    ]

    if (
        len(names)
        != len(set(names))
    ):

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None,
        }

    if (
        len(order)
        != len(set(order))
    ):

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None,
        }

    if set(names) != set(order):

        return {
            "freezeId": freeze_id,
            "selected": None,
            "results": [],
            "packageManifest": None,
        }

    latencies = body[
        "latencies"
    ]

    for name, value in latencies.items():

        if not is_nonempty_string(
            name
        ):
            return {
                "freezeId": freeze_id,
                "selected": None,
                "results": [],
                "packageManifest": None,
            }

        if not is_finite_number(
            value
        ):
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

    candidate_map = {
        c["name"]: c
        for c in candidates
    }

    results = []

    for name in order:

        results.append(
            evaluate_candidate(
                candidate_map[name],
                body["rows"],
                policy,
                latencies,
            )
        )

    admitted = [
        r
        for r in results
        if r["admitted"]
    ]

    selected = None
    package_manifest = None

    if admitted:

        order_index = {
            name: i
            for i, name
            in enumerate(order)
        }

        winner = min(
            admitted,
            key=lambda r: (
                r["totalBytes"],
                r["latencyMs"],
                order_index[
                    r["name"]
                ],
                utf8_key(
                    r["name"]
                ),
            ),
        )

        selected = winner[
            "name"
        ]

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
# POST /quantize
# ============================================================

@app.post("/quantize")
async def quantize(request: Request):

    try:
        body = await request.json()

    except Exception:

        return JSONResponse(
            {
                "error":
                    "INVALID_INPUT"
            },
            status_code=400,
        )

    if not isinstance(
        body,
        dict,
    ):

        return JSONResponse(
            {
                "error":
                    "INVALID_INPUT"
            },
            status_code=400,
        )

    phase = body.get(
        "phase"
    )

    # ========================================================
    # FREEZE
    # ========================================================

    if phase == "freeze":

        valid, diagnostic = (
            validate_freeze_shape(
                body
            )
        )

        if not valid:

            print(
                "INVALID FREEZE REQUEST:",
                diagnostic,
                repr(body),
                flush=True,
            )

            return JSONResponse(
                {
                    "error":
                        "INVALID_INPUT"
                },
                status_code=400,
            )

        freeze_id = body[
            "freezeId"
        ]

        fingerprint = sha256_hex(
            compact_json_bytes(
                body
            )
        )

        # ----------------------------------------------------
        # Replay
        # ----------------------------------------------------

        if freeze_id in FREEZES:

            saved = FREEZES[
                freeze_id
            ]

            if (
                saved[
                    "fingerprint"
                ]
                == fingerprint
            ):

                return JSONResponse(
                    saved[
                        "response"
                    ],
                    status_code=200,
                )

            # Different input with same freezeId.
            return JSONResponse(
                {
                    "error":
                        "FREEZE_ID_CONFLICT"
                },
                status_code=409,
            )

        # ----------------------------------------------------
        # Create
        # ----------------------------------------------------

        response = (
            create_freeze_response(
                body
            )
        )

        # ----------------------------------------------------
        # IMPORTANT:
        #
        # Do not reserve a freezeId if the request contains
        # duplicate candidate names.
        # ----------------------------------------------------

        names = [
            c["name"]
            for c in body[
                "candidates"
            ]
        ]

        has_duplicate_names = (
            len(names)
            != len(set(names))
        )

        if not has_duplicate_names:

            FREEZES[
                freeze_id
            ] = {
                "fingerprint":
                    fingerprint,
                "response":
                    response,
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
                {
                    "error":
                        "INVALID_INPUT"
                },
                status_code=400,
            )

        freeze_id = body[
            "freezeId"
        ]

        if freeze_id not in FREEZES:

            return JSONResponse({
                "freezeId": freeze_id,
                "selected": None,
                "results": [],
                "packageManifest": None,
            })

        response = (
            create_select_response(
                body,
                FREEZES[
                    freeze_id
                ][
                    "response"
                ],
            )
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
        {
            "error":
                "INVALID_INPUT"
        },
        status_code=400,
    )


@app.get("/")
async def root():
    return {
        "ok": True,
        "endpoint": "/quantize",
    }
