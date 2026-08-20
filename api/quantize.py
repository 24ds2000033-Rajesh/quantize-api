import hashlib
import json
import math
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

# Stateful storage for warm Vercel function instances.
FREEZES = {}


def jbytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ukey(value: str):
    return value.encode("utf-8")


def sorted_codes(codes):
    return sorted(set(codes), key=ukey)


def add_code(codes, code):
    if code not in codes:
        codes.append(code)


def nonempty_string(v):
    return isinstance(v, str) and len(v) > 0


def finite_number(v):
    return (
        isinstance(v, (int, float))
        and not isinstance(v, bool)
        and math.isfinite(float(v))
    )


def safe_int(v):
    return (
        isinstance(v, int)
        and not isinstance(v, bool)
        and 0 <= v <= 9007199254740991
    )


def unique_strings(v, allow_empty=True):
    if not isinstance(v, list):
        return False
    if not allow_empty and not v:
        return False
    if any(not nonempty_string(x) for x in v):
        return False
    return len(v) == len(set(v))


# ============================================================
# MANIFEST
# ============================================================

def make_inventory(candidate):
    files = candidate.get("files")

    if not isinstance(files, dict) or len(files) == 0:
        return False, [], None, None

    inventory = []

    for filename in sorted(files.keys(), key=ukey):
        if not isinstance(filename, str) or filename == "":
            return False, [], None, None

        content = files[filename]

        # File contents are data and must be UTF-8 strings.
        if not isinstance(content, str):
            return False, [], None, None

        raw = content.encode("utf-8")

        inventory.append({
            "name": filename,
            "bytes": len(raw),
            "sha256": sha256(raw),
        })

    total = sum(x["bytes"] for x in inventory)
    package_digest = sha256(jbytes(inventory))

    return True, inventory, total, package_digest


# ============================================================
# FREEZE
# ============================================================

def valid_freeze_request(body):
    if not isinstance(body, dict):
        return False

    if body.get("phase") != "freeze":
        return False

    freeze_id = body.get("freezeId")
    if not nonempty_string(freeze_id) or len(freeze_id) > 128:
        return False

    if not nonempty_string(body.get("calibrationDigest")):
        return False

    if not nonempty_string(body.get("tokenizerDigest")):
        return False

    allowed = body.get("allowedUnsupportedReasons")
    if not unique_strings(allowed, allow_empty=True):
        return False

    candidates = body.get("candidates")

    if not isinstance(candidates, list) or len(candidates) == 0:
        return False

    names = []

    for c in candidates:
        if not isinstance(c, dict):
            return False

        if not nonempty_string(c.get("name")):
            return False

        names.append(c["name"])

        # files is mandatory and must be a non-empty object
        files = c.get("files")
        if not isinstance(files, dict) or len(files) == 0:
            return False

        # Validate every filename/content without imposing
        # restrictions on optional unsupportedReason.
        for filename, content in files.items():
            if not isinstance(filename, str) or filename == "":
                return False
            if not isinstance(content, str):
                return False

    if len(names) != len(set(names)):
        return False

    return True


def make_freeze(body):
    calibration = body["calibrationDigest"]
    tokenizer = body["tokenizerDigest"]
    allowed = set(body["allowedUnsupportedReasons"])

    output = []

    for c in body["candidates"]:
        name = c["name"]

        ok, inventory, total, package = make_inventory(c)

        if not ok:
            output.append({
                "name": name,
                "status": "invalid",
                "inventory": [],
                "totalBytes": None,
                "packageDigest": None,
                "reasonCodes": ["INVALID_INPUT"],
            })
            continue

        codes = []
        status = "frozen"

        # Treat any non-null/non-empty unsupportedReason as a reason.
        reason = c.get("unsupportedReason")

        if reason is not None and reason != "":
            if isinstance(reason, str) and reason in allowed:
                status = "unsupported"
            else:
                status = "invalid"
                add_code(codes, "UNALLOWED_UNSUPPORTED_REASON")

        else:
            if c.get("loadable") is not True:
                status = "invalid"
                add_code(codes, "NOT_LOADABLE")

            if c.get("calibrationDigest") != calibration:
                status = "invalid"
                add_code(codes, "CALIBRATION_MISMATCH")

            if c.get("tokenizerDigest") != tokenizer:
                status = "invalid"
                add_code(codes, "TOKENIZER_MISMATCH")

        output.append({
            "name": name,
            "status": status,
            "inventory": inventory,
            "totalBytes": total,
            "packageDigest": package,
            "reasonCodes": sorted_codes(codes),
        })

    output.sort(key=lambda x: ukey(x["name"]))

    return {
        "freezeId": body["freezeId"],
        "candidates": output,
    }


# ============================================================
# MANIFEST RECOMPUTATION
# ============================================================

def verify_manifest(candidate):
    inventory = candidate.get("inventory")

    if not isinstance(inventory, list):
        return False, None, None

    rebuilt = []
    previous = None

    for item in inventory:
        if not isinstance(item, dict):
            return False, None, None

        if set(item.keys()) != {"name", "bytes", "sha256"}:
            return False, None, None

        name = item.get("name")
        nbytes = item.get("bytes")
        digest = item.get("sha256")

        if not nonempty_string(name):
            return False, None, None

        if not safe_int(nbytes):
            return False, None, None

        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or digest != digest.lower()
            or any(ch not in "0123456789abcdef" for ch in digest)
        ):
            return False, None, None

        if previous is not None and ukey(name) <= ukey(previous):
            return False, None, None

        previous = name

        rebuilt.append({
            "name": name,
            "bytes": nbytes,
            "sha256": digest,
        })

    names = [x["name"] for x in rebuilt]

    if len(names) != len(set(names)):
        return False, None, None

    total = sum(x["bytes"] for x in rebuilt)
    digest = sha256(jbytes(rebuilt))

    if candidate.get("totalBytes") != total:
        return False, None, None

    if candidate.get("packageDigest") != digest:
        return False, None, None

    return True, total, digest


# ============================================================
# SELECT VALIDATION
# ============================================================

def valid_policy(policy):
    if not isinstance(policy, dict):
        return False

    if not safe_int(policy.get("maxBytes")):
        return False

    if not finite_number(policy.get("aggregateFloor")):
        return False

    if not 0 <= float(policy["aggregateFloor"]) <= 1:
        return False

    slices = policy.get("requiredSlices")

    if not isinstance(slices, dict):
        return False

    for name, floor in slices.items():
        if not nonempty_string(name):
            return False
        if not finite_number(floor):
            return False
        if not 0 <= float(floor) <= 1:
            return False

    if not finite_number(policy.get("maxLatencyMs")):
        return False

    if float(policy["maxLatencyMs"]) < 0:
        return False

    if not unique_strings(
        policy.get("candidateOrder"),
        allow_empty=False,
    ):
        return False

    return True


def valid_select_request(body):
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

    if not isinstance(body.get("latencies"), dict):
        return False

    return True


def accuracy(correct, total):
    if total == 0:
        return None
    return float(f"{correct / total:.12f}")


# ============================================================
# SELECT
# ============================================================

def calculate(candidate, rows, policy, latencies):
    name = candidate["name"]

    codes = []

    aggregate = None
    slices = {}
    total_bytes = None
    latency = None

    # -------------------------
    # lineage
    # -------------------------

    if candidate.get("status") != "frozen":
        add_code(codes, "INVALID_LINEAGE")

    # -------------------------
    # manifest
    # -------------------------

    manifest_ok, total, _ = verify_manifest(candidate)

    if manifest_ok:
        total_bytes = total
    else:
        add_code(codes, "INVALID_MANIFEST")

    # -------------------------
    # predictions
    # -------------------------

    prediction_ok = True
    aggregate_correct = 0

    slice_total = {}
    slice_correct = {}

    for row in rows:
        predictions = row.get("predictions")

        if not isinstance(predictions, dict):
            prediction_ok = False
            break

        if name not in predictions:
            prediction_ok = False
            break

        prediction = predictions[name]
        label = row.get("label")

        # Binary integer predictions and labels only.
        if (
            isinstance(prediction, bool)
            or not isinstance(prediction, int)
            or prediction not in (0, 1)
        ):
            prediction_ok = False
            break

        if (
            isinstance(label, bool)
            or not isinstance(label, int)
            or label not in (0, 1)
        ):
            prediction_ok = False
            break

        slice_name = row.get("slice")

        if not nonempty_string(slice_name):
            prediction_ok = False
            break

        slice_total[slice_name] = slice_total.get(slice_name, 0) + 1

        if prediction == label:
            aggregate_correct += 1
            slice_correct[slice_name] = (
                slice_correct.get(slice_name, 0) + 1
            )
        else:
            slice_correct.setdefault(slice_name, 0)

    if not prediction_ok:
        add_code(codes, "INVALID_PREDICTIONS")
    else:
        aggregate = accuracy(
            aggregate_correct,
            len(rows),
        )

        for slice_name in sorted(slice_total.keys(), key=ukey):
            slices[slice_name] = accuracy(
                slice_correct[slice_name],
                slice_total[slice_name],
            )

        # Aggregate floor
        if aggregate is None or aggregate < float(
            policy["aggregateFloor"]
        ):
            add_code(codes, "AGGREGATE_FLOOR")

        # Required slices
        for slice_name, floor in policy["requiredSlices"].items():
            if slice_name not in slice_total:
                add_code(
                    codes,
                    f"MISSING_SLICE:{slice_name}",
                )
            elif slices[slice_name] < float(floor):
                add_code(
                    codes,
                    f"SLICE_FLOOR:{slice_name}",
                )

    # -------------------------
    # size
    # -------------------------

    if total_bytes is not None:
        if total_bytes > policy["maxBytes"]:
            add_code(codes, "SIZE_LIMIT")

    # -------------------------
    # latency
    # -------------------------

    if name in latencies:
        value = latencies[name]

        if finite_number(value) and float(value) >= 0:
            latency = value

            if float(value) > float(policy["maxLatencyMs"]):
                add_code(codes, "LATENCY_LIMIT")
        else:
            add_code(codes, "LATENCY_LIMIT")
    else:
        add_code(codes, "LATENCY_LIMIT")

    codes = sorted_codes(codes)

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
# HTTP
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

        if not valid_freeze_request(body):
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400,
            )

        freeze_id = body["freezeId"]

        fingerprint = sha256(jbytes(body))

        if freeze_id in FREEZES:
            old = FREEZES[freeze_id]

            if old["fingerprint"] == fingerprint:
                return JSONResponse(
                    old["response"],
                    status_code=200,
                )

            return JSONResponse(
                {"error": "FREEZE_ID_CONFLICT"},
                status_code=409,
            )

        response = make_freeze(body)

        FREEZES[freeze_id] = {
            "fingerprint": fingerprint,
            "response": response,
        }

        return JSONResponse(response)

    # ========================================================
    # SELECT
    # ========================================================

    if phase == "select":

        if not valid_select_request(body):
            return JSONResponse(
                {"error": "INVALID_INPUT"},
                status_code=400,
            )

        freeze_id = body["freezeId"]

        if freeze_id not in FREEZES:
            return JSONResponse({
                "freezeId": freeze_id,
                "selected": None,
                "results": [],
                "packageManifest": None,
            })

        frozen = FREEZES[freeze_id]["response"]

        # The supplied candidates must exactly equal the frozen
        # response candidates.
        if jbytes(body["candidates"]) != jbytes(
            frozen["candidates"]
        ):
            return JSONResponse({
                "freezeId": freeze_id,
                "selected": None,
                "results": [],
                "packageManifest": None,
            })

        policy = body["policy"]

        if not valid_policy(policy):
            return JSONResponse({
                "freezeId": freeze_id,
                "selected": None,
                "results": [],
                "packageManifest": None,
            })

        names = [
            c.get("name")
            for c in body["candidates"]
        ]

        order = policy["candidateOrder"]

        if (
            len(names) != len(set(names))
            or set(names) != set(order)
        ):
            return JSONResponse({
                "freezeId": freeze_id,
                "selected": None,
                "results": [],
                "packageManifest": None,
            })

        # Validate latency values.
        for name, value in body["latencies"].items():
            if (
                not nonempty_string(name)
                or not finite_number(value)
                or float(value) < 0
            ):
                return JSONResponse({
                    "freezeId": freeze_id,
                    "selected": None,
                    "results": [],
                    "packageManifest": None,
                })

        candidate_map = {
            c["name"]: c
            for c in body["candidates"]
        }

        results = []

        for name in order:
            results.append(
                calculate(
                    candidate_map[name],
                    body["rows"],
                    policy,
                    body["latencies"],
                )
            )

        admitted = [
            r for r in results
            if r["admitted"]
        ]

        selected = None
        package_manifest = None

        if admitted:
            order_index = {
                name: i
                for i, name in enumerate(order)
            }

            winner = min(
                admitted,
                key=lambda r: (
                    r["totalBytes"],
                    r["latencyMs"],
                    order_index[r["name"]],
                    ukey(r["name"]),
                ),
            )

            selected = winner["name"]
            package_manifest = candidate_map[selected]

        return JSONResponse({
            "freezeId": freeze_id,
            "selected": selected,
            "results": results,
            "packageManifest": package_manifest,
        })

    # ========================================================
    # UNKNOWN PHASE
    # ========================================================

    return JSONResponse(
        {"error": "INVALID_INPUT"},
        status_code=400,
    )


@app.get("/")
async def root():
    return {"ok": True}
