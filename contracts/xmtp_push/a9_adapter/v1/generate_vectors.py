#!/usr/bin/env python3
"""Generate the deterministic XMTP A9 bridge conformance vectors.

All seeds and HMAC keys in this file are public TEST-ONLY material. They must
never be provisioned outside a test process.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import struct
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parent
VECTORS = ROOT / "vectors"
MAX_IJSON_INTEGER = (1 << 53) - 1
THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000

ASSERTION_DOMAIN = b"Hytch A9 bridge assertion v1\x00"
CONTROL_DOMAIN = b"Hytch A9 bridge control v1\x00"
WATERMARK_DOMAIN = b"Hytch A9 bridge control watermark v1\x00"
KEYSET_DOMAIN = b"Hytch A9 bridge keyset v1\x00"
ROSTER_DOMAIN = b"Hytch A9 bridge roster v1\x00"
TUPLE_DOMAIN = b"Hytch A9 push tuple v1\x00"
TOPIC_DOMAIN = b"Hytch A9 bridge topic v1\x00"


def canonical_json(value: Any) -> bytes:
    """Return the contract's ASCII-only RFC-8785 profile."""

    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def pretty_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    ).encode("ascii")


def b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def lowerhex_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def key_id(prefix: str, value: bytes) -> str:
    return prefix + hashlib.sha256(value).hexdigest()


def public_key(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def sign_flat(
    unsigned: dict[str, Any],
    *,
    domain: bytes,
    private_key: Ed25519PrivateKey,
    signature_field: str = "signature_base64url",
) -> tuple[dict[str, Any], bytes, bytes]:
    canonical = canonical_json(unsigned)
    signing_input = domain + canonical
    signed = dict(unsigned)
    signed[signature_field] = b64u(private_key.sign(signing_input))
    return signed, canonical, signing_input


def fixed_time(value: str) -> datetime:
    parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    return parsed.replace(tzinfo=UTC)


def wire_time(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.") + (
        f"{value.microsecond // 1000:03d}Z"
    )


def hmac_sha256(key: bytes, value: bytes) -> bytes:
    return hmac.new(key, value, hashlib.sha256).digest()


def roster_commitment(key: bytes, environment: str, roster_digest: bytes) -> bytes:
    environment_bytes = environment.encode("ascii")
    return hmac_sha256(
        key,
        ROSTER_DOMAIN
        + struct.pack(">B", len(environment_bytes))
        + environment_bytes
        + roster_digest,
    )


def tuple_commitment(
    key: bytes,
    *,
    environment: str,
    account_incarnation_id: str,
    hytch_conversation_id: str,
    conversation_generation: int,
    roster_version: int,
    roster_commitment_bytes: bytes,
    transport_conversation_id: str,
) -> bytes:
    environment_bytes = environment.encode("ascii")
    state = b"ACTIVE"
    transport = transport_conversation_id.encode("ascii")
    return hmac_sha256(
        key,
        TUPLE_DOMAIN
        + struct.pack(">B", len(environment_bytes))
        + environment_bytes
        + uuid.UUID(account_incarnation_id).bytes
        + uuid.UUID(hytch_conversation_id).bytes
        + struct.pack(">I", conversation_generation)
        + struct.pack(">I", roster_version)
        + roster_commitment_bytes
        + struct.pack(">B", len(state))
        + state
        + struct.pack(">H", len(transport))
        + transport,
    )


def topic_binding(key: bytes, topic_bytes: bytes) -> bytes:
    return hmac_sha256(
        key,
        TOPIC_DOMAIN + struct.pack(">I", len(topic_bytes)) + topic_bytes,
    )


def signed_vector(
    signed: dict[str, Any],
    canonical_unsigned: bytes,
    signing_input: bytes,
) -> dict[str, Any]:
    return {
        "value": signed,
        "canonical_unsigned_utf8": canonical_unsigned.decode("ascii"),
        "canonical_unsigned_sha256": lowerhex_sha256(canonical_unsigned),
        "signing_input_hex": signing_input.hex(),
        "signed_object_sha256": lowerhex_sha256(canonical_json(signed)),
    }


def mutate_b64u_byte(value: str, index: int = 0) -> str:
    padded = value + ("=" * ((4 - len(value) % 4) % 4))
    decoded = bytearray(base64.urlsafe_b64decode(padded))
    decoded[index] ^= 0x01
    return b64u(bytes(decoded))


def service_jwt_vector(
    *,
    private_key: Ed25519PrivateKey,
    signing_key_id: str,
    issued_at: datetime,
    environment: str,
    method: str,
    path: str,
    request_body: bytes,
    jti: str,
) -> dict[str, Any]:
    header = {
        "alg": "EdDSA",
        "kid": signing_key_id,
        "typ": "JWT",
    }
    claims = {
        "aud": "hytch.xmtp-push-bridge.a9-control",
        "environment": environment,
        "exp": int(issued_at.timestamp()) + 60,
        "iat": int(issued_at.timestamp()),
        "iss": "hytch-modern-api",
        "jti": jti,
        "method": method,
        "nbf": int(issued_at.timestamp()) - 1,
        "path": path,
        "request_sha256": lowerhex_sha256(request_body),
        "sub": "xmtp-push-a9-adapter",
    }
    header_segment = b64u(canonical_json(header))
    claims_segment = b64u(canonical_json(claims))
    signing_input = f"{header_segment}.{claims_segment}".encode("ascii")
    signature = private_key.sign(signing_input)
    return {
        "claims": claims,
        "compact": f"{header_segment}.{claims_segment}.{b64u(signature)}",
        "header": header,
        "signing_input_utf8": signing_input.decode("ascii"),
    }


def build_positive() -> dict[str, Any]:
    root_seed = bytes(range(1, 33))
    control_seed = bytes(range(33, 65))
    next_control_seed = hashlib.sha256(b"hytch-a9-next-control-test-seed").digest()
    service_seed = bytes(range(65, 97))
    roster_key = bytes(range(97, 129))
    tuple_key = bytes(range(129, 161))
    topic_key = bytes(range(161, 193))
    next_topic_key = hashlib.sha256(b"hytch-a9-next-topic-test-key").digest()
    route_key = bytes(range(193, 225))
    sender_key_current = bytes(range(7, 39))
    sender_key_next = bytes(range(39, 71))

    root_private = Ed25519PrivateKey.from_private_bytes(root_seed)
    control_private = Ed25519PrivateKey.from_private_bytes(control_seed)
    next_control_private = Ed25519PrivateKey.from_private_bytes(next_control_seed)
    service_private = Ed25519PrivateKey.from_private_bytes(service_seed)
    root_public = public_key(root_private)
    control_public = public_key(control_private)
    next_control_public = public_key(next_control_private)
    service_public = public_key(service_private)

    root_key_id = key_id("ed25519-sha256:", root_public)
    control_key_id = key_id("ed25519-sha256:", control_public)
    next_control_key_id = key_id("ed25519-sha256:", next_control_public)
    service_key_id = key_id("ed25519-sha256:", service_public)
    roster_key_id = key_id("hmac-sha256:", roster_key)
    tuple_key_id = key_id("hmac-sha256:", tuple_key)
    topic_key_id = key_id("hmac-sha256:", topic_key)
    next_topic_key_id = key_id("hmac-sha256:", next_topic_key)

    issued_at = fixed_time("2026-07-29T17:00:00.000Z")
    expires_at = issued_at + timedelta(seconds=30)
    keyset_expires_at = issued_at + timedelta(hours=1)
    unix_ms = int(issued_at.timestamp() * 1000)
    topic_key_epoch = unix_ms // THIRTY_DAYS_MS
    boundary_ms = (topic_key_epoch + 1) * THIRTY_DAYS_MS
    boundary_at = datetime.fromtimestamp(boundary_ms / 1000, tz=UTC)

    environment = "dev"
    account_incarnation_id = "2bf32592-a919-43b3-9360-d1fd360df82a"
    hytch_conversation_id = "019f9faf-adf9-725d-a24e-07db1f83516b"
    group_identifier = bytes(range(32))
    transport_conversation_id = group_identifier.hex()
    topic_bytes = b"\x00" + group_identifier
    roster_digest = hashlib.sha256(b"hytch-a9-roster-vector-v1").digest()
    roster_value = roster_commitment(roster_key, environment, roster_digest)
    tuple_value = tuple_commitment(
        tuple_key,
        environment=environment,
        account_incarnation_id=account_incarnation_id,
        hytch_conversation_id=hytch_conversation_id,
        conversation_generation=3,
        roster_version=9,
        roster_commitment_bytes=roster_value,
        transport_conversation_id=transport_conversation_id,
    )
    topic_value = topic_binding(topic_key, topic_bytes)

    installation_binding_id = b64u(bytes(range(16)))
    binding_id = b64u(bytes(range(16, 32)))
    lease_id = b64u(bytes(range(32, 48)))
    sequencer_epoch = b64u(bytes(range(48, 64)))

    assertion_unsigned = {
        "audience": "hytch.xmtp-push-bridge.a9-control",
        "binding_id": binding_id,
        "binding_version": 4,
        "conversation_generation": 3,
        "environment": environment,
        "expires_at": wire_time(expires_at),
        "installation_binding_id": installation_binding_id,
        "issued_at": wire_time(issued_at),
        "lease_id": lease_id,
        "protocol": "hytch.a9-bridge-assertion",
        "purpose": "conversation_message_push",
        "roster_commitment": b64u(roster_value),
        "roster_commitment_key_id": roster_key_id,
        "roster_version": 9,
        "schema_version": 1,
        "signature_algorithm": "Ed25519",
        "signing_key_id": control_key_id,
        "state": "ACTIVE",
        "stream_sequence": 7,
        "topic_binding": b64u(topic_value),
        "topic_key_epoch": topic_key_epoch,
        "tuple_commitment": b64u(tuple_value),
        "tuple_commitment_key_id": tuple_key_id,
    }
    assertion, assertion_canonical, assertion_input = sign_flat(
        assertion_unsigned,
        domain=ASSERTION_DOMAIN,
        private_key=control_private,
    )
    assertion_hash = b64u(hashlib.sha256(canonical_json(assertion)).digest())

    control_unsigned = {
        "action": "UPSERT",
        "assertion": assertion,
        "assertion_hash": assertion_hash,
        "audience": "hytch.xmtp-push-bridge.a9-control",
        "binding_id": binding_id,
        "binding_version": 4,
        "environment": environment,
        "expected_binding_version": 3,
        "expected_previous_sequence": 6,
        "expires_at": wire_time(expires_at),
        "idempotency_key": "d31f0c8a-5d8c-48a0-8392-b86fb50cd0de",
        "installation_binding_id": installation_binding_id,
        "issued_at": wire_time(issued_at),
        "protocol": "hytch.a9-bridge-control",
        "reason_code": None,
        "schema_version": 1,
        "sequencer_epoch": sequencer_epoch,
        "signature_algorithm": "Ed25519",
        "signing_key_id": control_key_id,
        "stream_sequence": 7,
    }
    control, control_canonical, control_input = sign_flat(
        control_unsigned,
        domain=CONTROL_DOMAIN,
        private_key=control_private,
    )

    watermark_unsigned = {
        "audience": "hytch.xmtp-push-bridge.a9-control",
        "committed_through_stream_sequence": 7,
        "environment": environment,
        "expires_at": wire_time(expires_at),
        "installation_binding_id": installation_binding_id,
        "issued_at": wire_time(issued_at),
        "protocol": "hytch.a9-control-watermark",
        "schema_version": 1,
        "sequencer_epoch": sequencer_epoch,
        "signature_algorithm": "Ed25519",
        "signing_key_id": control_key_id,
        "status": "CURRENT",
        "uncertainty_reason": "NONE",
        "watermark_sequence": 41,
    }
    watermark, watermark_canonical, watermark_input = sign_flat(
        watermark_unsigned,
        domain=WATERMARK_DOMAIN,
        private_key=control_private,
    )

    keyset_unsigned = {
        "commitment_keys": [
            {
                "key_id": roster_key_id,
                "not_after": wire_time(issued_at + timedelta(days=30)),
                "not_before": wire_time(issued_at - timedelta(minutes=5)),
                "purpose": "ROSTER",
                "topic_key_epoch": None,
            },
            {
                "key_id": topic_key_id,
                "not_after": wire_time(boundary_at + timedelta(seconds=60)),
                "not_before": wire_time(issued_at - timedelta(minutes=5)),
                "purpose": "TOPIC",
                "topic_key_epoch": topic_key_epoch,
            },
            {
                "key_id": tuple_key_id,
                "not_after": wire_time(issued_at + timedelta(days=30)),
                "not_before": wire_time(issued_at - timedelta(minutes=5)),
                "purpose": "TUPLE",
                "topic_key_epoch": None,
            },
        ],
        "environment": environment,
        "expires_at": wire_time(keyset_expires_at),
        "issued_at": wire_time(issued_at),
        "keys": [
            {
                "key_id": control_key_id,
                "not_after": wire_time(issued_at + timedelta(days=30)),
                "not_before": wire_time(issued_at - timedelta(minutes=5)),
                "public_key_base64url": b64u(control_public),
                "state": "SIGN",
                "use": "A9_CONTROL",
            },
            {
                "key_id": service_key_id,
                "not_after": wire_time(issued_at + timedelta(days=30)),
                "not_before": wire_time(issued_at - timedelta(minutes=5)),
                "public_key_base64url": b64u(service_public),
                "state": "SIGN",
                "use": "SERVICE_AUTH",
            },
        ],
        "keyset_sequence": 17,
        "protocol": "hytch.a9-bridge-keyset",
        "root_signature_algorithm": "Ed25519",
        "root_signing_key_id": root_key_id,
        "schema_version": 1,
    }
    keyset, keyset_canonical, keyset_input = sign_flat(
        keyset_unsigned,
        domain=KEYSET_DOMAIN,
        private_key=root_private,
        signature_field="root_signature_base64url",
    )

    control_activation_at = issued_at + timedelta(hours=24)
    keyset_transition_unsigned = {
        **keyset_unsigned,
        "keys": [
            {
                "key_id": control_key_id,
                "not_after": wire_time(control_activation_at + timedelta(seconds=90)),
                "not_before": wire_time(issued_at - timedelta(minutes=5)),
                "public_key_base64url": b64u(control_public),
                "state": "SIGN",
                "use": "A9_CONTROL",
            },
            {
                "key_id": next_control_key_id,
                "not_after": wire_time(control_activation_at + timedelta(days=30)),
                "not_before": wire_time(control_activation_at),
                "public_key_base64url": b64u(next_control_public),
                "state": "VERIFY_ONLY",
                "use": "A9_CONTROL",
            },
            {
                "key_id": service_key_id,
                "not_after": wire_time(issued_at + timedelta(days=30)),
                "not_before": wire_time(issued_at - timedelta(minutes=5)),
                "public_key_base64url": b64u(service_public),
                "state": "SIGN",
                "use": "SERVICE_AUTH",
            },
        ],
        "keyset_sequence": 18,
    }
    keyset_transition, keyset_transition_canonical, keyset_transition_input = sign_flat(
        keyset_transition_unsigned,
        domain=KEYSET_DOMAIN,
        private_key=root_private,
        signature_field="root_signature_base64url",
    )

    keyset_cutover_unsigned = {
        **keyset_transition_unsigned,
        "expires_at": wire_time(control_activation_at + timedelta(hours=1)),
        "issued_at": wire_time(control_activation_at),
        "keys": [
            {
                "key_id": next_control_key_id,
                "not_after": wire_time(control_activation_at + timedelta(days=30)),
                "not_before": wire_time(control_activation_at),
                "public_key_base64url": b64u(next_control_public),
                "state": "SIGN",
                "use": "A9_CONTROL",
            },
            {
                "key_id": control_key_id,
                "not_after": wire_time(control_activation_at + timedelta(seconds=90)),
                "not_before": wire_time(issued_at - timedelta(minutes=5)),
                "public_key_base64url": b64u(control_public),
                "state": "VERIFY_ONLY",
                "use": "A9_CONTROL",
            },
            {
                "key_id": service_key_id,
                "not_after": wire_time(issued_at + timedelta(days=30)),
                "not_before": wire_time(issued_at - timedelta(minutes=5)),
                "public_key_base64url": b64u(service_public),
                "state": "SIGN",
                "use": "SERVICE_AUTH",
            },
        ],
        "keyset_sequence": 19,
    }
    keyset_cutover, keyset_cutover_canonical, keyset_cutover_input = sign_flat(
        keyset_cutover_unsigned,
        domain=KEYSET_DOMAIN,
        private_key=root_private,
        signature_field="root_signature_base64url",
    )

    current_sender_period = unix_ms // THIRTY_DAYS_MS
    policy_control = canonical_json(
        {
            "fixture_only": True,
            "gate": 6,
            "verdict": "VALID",
        }
    )
    receive_capability = canonical_json(
        {
            "fixture_only": True,
            "gate": 6,
            "verdict": "VALID",
        }
    )
    subscription_request = {
        "account_incarnation_id": account_incarnation_id,
        "apns_token_base64url": b64u(hashlib.sha256(b"test-apns-token").digest()),
        "environment": environment,
        "expected_subscription_generation": 11,
        "idempotency_key": "e6afeaae-8e4d-47ba-ad6b-c514ea76c0c7",
        "installation_binding_id": installation_binding_id,
        "legacy_installation_id": hashlib.sha256(b"legacy-installation").hexdigest(),
        "payload_schema": "hytch_push_wrapper_v1",
        "policy_control_base64url": b64u(policy_control),
        "protocol": "hytch.a9-subscription-replace",
        "schema_version": 1,
        "sequencer_epoch": sequencer_epoch,
        "subscription_generation": 12,
        "subscriptions": [
            {
                "assertion_hash": assertion_hash,
                "binding_id": binding_id,
                "binding_version": 4,
                "hmac_keys": [
                    {
                        "key_base64url": b64u(sender_key_current),
                        "thirty_day_periods_since_epoch": current_sender_period,
                    },
                    {
                        "key_base64url": b64u(sender_key_next),
                        "thirty_day_periods_since_epoch": current_sender_period + 1,
                    },
                ],
                "receive_capability_base64url": b64u(receive_capability),
                "route_key_base64url": b64u(route_key),
                "route_key_epoch": 5,
                "topic_base64url": b64u(topic_bytes),
                "topic_binding": b64u(topic_value),
                "topic_key_epoch": topic_key_epoch,
                "transport_conversation_id": transport_conversation_id,
            }
        ],
    }
    subscription_canonical = canonical_json(subscription_request)

    subscription_service_jwt = service_jwt_vector(
        private_key=service_private,
        signing_key_id=service_key_id,
        issued_at=issued_at,
        environment=environment,
        method="PUT",
        path="/internal/v1/xmtp-push/subscriptions:replace",
        request_body=subscription_canonical,
        jti="a47ef0b2-f1ec-4fd1-bff2-12f0fe80c8f1",
    )
    control_service_jwt = service_jwt_vector(
        private_key=service_private,
        signing_key_id=service_key_id,
        issued_at=issued_at,
        environment=environment,
        method="POST",
        path="/internal/v1/xmtp-push/a9-authority:apply",
        request_body=canonical_json(control),
        jti="dc1c95ec-04d7-4cbf-a618-a04329af56a5",
    )
    watermark_service_jwt = service_jwt_vector(
        private_key=service_private,
        signing_key_id=service_key_id,
        issued_at=issued_at,
        environment=environment,
        method="POST",
        path="/internal/v1/xmtp-push/a9-watermarks:apply",
        request_body=canonical_json(watermark),
        jti="3d75a1e0-d676-48d8-8656-3a892e283327",
    )

    result = {
        "accepted_stream_sequence": 7,
        "environment": environment,
        "idempotent_replay": False,
        "installation_binding_id": installation_binding_id,
        "outcome": "APPLIED",
        "protocol": "hytch.a9-vault-cas-result",
        "schema_version": 1,
        "sequencer_epoch": sequencer_epoch,
        "state": "ACTIVE",
        "subscription_generation": 12,
    }

    next_topic_value = topic_binding(next_topic_key, topic_bytes)
    topic_transition_keyset_unsigned = {
        **keyset_cutover_unsigned,
        "commitment_keys": [
            {
                "key_id": roster_key_id,
                "not_after": wire_time(issued_at + timedelta(days=30)),
                "not_before": wire_time(issued_at - timedelta(minutes=5)),
                "purpose": "ROSTER",
                "topic_key_epoch": None,
            },
            {
                "key_id": topic_key_id,
                "not_after": wire_time(boundary_at + timedelta(seconds=60)),
                "not_before": wire_time(issued_at - timedelta(minutes=5)),
                "purpose": "TOPIC",
                "topic_key_epoch": topic_key_epoch,
            },
            {
                "key_id": next_topic_key_id,
                "not_after": wire_time(boundary_at + timedelta(days=30, seconds=60)),
                "not_before": wire_time(boundary_at),
                "purpose": "TOPIC",
                "topic_key_epoch": topic_key_epoch + 1,
            },
            {
                "key_id": tuple_key_id,
                "not_after": wire_time(issued_at + timedelta(days=30)),
                "not_before": wire_time(issued_at - timedelta(minutes=5)),
                "purpose": "TUPLE",
                "topic_key_epoch": None,
            },
        ],
        "expires_at": wire_time(boundary_at + timedelta(minutes=55)),
        "issued_at": wire_time(boundary_at - timedelta(minutes=5)),
        "keys": [
            {
                "key_id": next_control_key_id,
                "not_after": wire_time(control_activation_at + timedelta(days=30)),
                "not_before": wire_time(control_activation_at),
                "public_key_base64url": b64u(next_control_public),
                "state": "SIGN",
                "use": "A9_CONTROL",
            },
            {
                "key_id": service_key_id,
                "not_after": wire_time(issued_at + timedelta(days=30)),
                "not_before": wire_time(issued_at - timedelta(minutes=5)),
                "public_key_base64url": b64u(service_public),
                "state": "SIGN",
                "use": "SERVICE_AUTH",
            },
        ],
        "keyset_sequence": 20,
    }
    (
        topic_transition_keyset,
        topic_transition_keyset_canonical,
        topic_transition_keyset_input,
    ) = sign_flat(
        topic_transition_keyset_unsigned,
        domain=KEYSET_DOMAIN,
        private_key=root_private,
        signature_field="root_signature_base64url",
    )

    old_boundary_assertion_unsigned = {
        **assertion_unsigned,
        "binding_id": b64u(hashlib.sha256(b"a9-old-boundary-binding").digest()[:16]),
        "binding_version": 5,
        "expires_at": wire_time(boundary_at + timedelta(seconds=29)),
        "issued_at": wire_time(boundary_at - timedelta(seconds=1)),
        "lease_id": b64u(hashlib.sha256(b"a9-old-boundary-lease").digest()[:16]),
        "signing_key_id": next_control_key_id,
        "stream_sequence": 8,
    }
    (
        old_boundary_assertion,
        old_boundary_assertion_canonical,
        old_boundary_assertion_input,
    ) = sign_flat(
        old_boundary_assertion_unsigned,
        domain=ASSERTION_DOMAIN,
        private_key=next_control_private,
    )
    new_boundary_assertion_unsigned = {
        **assertion_unsigned,
        "binding_id": b64u(hashlib.sha256(b"a9-new-boundary-binding").digest()[:16]),
        "binding_version": 6,
        "expires_at": wire_time(boundary_at + timedelta(seconds=30)),
        "issued_at": wire_time(boundary_at),
        "lease_id": b64u(hashlib.sha256(b"a9-new-boundary-lease").digest()[:16]),
        "signing_key_id": next_control_key_id,
        "stream_sequence": 9,
        "topic_binding": b64u(next_topic_value),
        "topic_key_epoch": topic_key_epoch + 1,
    }
    (
        new_boundary_assertion,
        new_boundary_assertion_canonical,
        new_boundary_assertion_input,
    ) = sign_flat(
        new_boundary_assertion_unsigned,
        domain=ASSERTION_DOMAIN,
        private_key=next_control_private,
    )

    return {
        "contract": "hytch.xmtp-push.a9-adapter.v1",
        "provenance": {
            "bridge_candidate_commit": "65f5c931815b49b1fe4365587a8eb3ec80d08377",
            "modern_api_reference_commit_unlanded": ("4c88119bcf07b6c991734cb7cf29a64b7b89effa"),
            "xmtpd_topic_commit": "6ae509c61de37d000184b46106326139d85ef255",
            "warning": "ALL PRIVATE SEEDS AND HMAC KEYS ARE PUBLIC TEST-ONLY MATERIAL",
        },
        "test_keys": {
            "control_private_seed_base64url": b64u(control_seed),
            "control_public_key_base64url": b64u(control_public),
            "control_signing_key_id": control_key_id,
            "next_control_private_seed_base64url": b64u(next_control_seed),
            "next_control_public_key_base64url": b64u(next_control_public),
            "next_control_signing_key_id": next_control_key_id,
            "root_private_seed_base64url": b64u(root_seed),
            "root_public_key_base64url": b64u(root_public),
            "root_signing_key_id": root_key_id,
            "roster_hmac_key_base64url": b64u(roster_key),
            "roster_hmac_key_id": roster_key_id,
            "service_auth_private_seed_base64url": b64u(service_seed),
            "service_auth_public_key_base64url": b64u(service_public),
            "service_auth_signing_key_id": service_key_id,
            "topic_hmac_key_base64url": b64u(topic_key),
            "topic_hmac_key_id": topic_key_id,
            "next_topic_hmac_key_base64url": b64u(next_topic_key),
            "next_topic_hmac_key_id": next_topic_key_id,
            "tuple_hmac_key_base64url": b64u(tuple_key),
            "tuple_hmac_key_id": tuple_key_id,
        },
        "source_tuple": {
            "account_incarnation_id": account_incarnation_id,
            "conversation_generation": 3,
            "environment": environment,
            "hytch_conversation_id": hytch_conversation_id,
            "roster_digest_base64url": b64u(roster_digest),
            "roster_version": 9,
            "state": "ACTIVE",
            "transport_conversation_id": transport_conversation_id,
        },
        "topic_resolver": {
            "group_identifier_hex": transport_conversation_id,
            "legacy_v3_topic": ("/xmtp/mls/1/g-" + transport_conversation_id + "/proto"),
            "topic_bytes_base64url": b64u(topic_bytes),
            "topic_bytes_hex": topic_bytes.hex(),
            "topic_bytes_length": len(topic_bytes),
            "topic_bytes_sha256": lowerhex_sha256(topic_bytes),
            "topic_kind_byte": 0,
        },
        "commitments": {
            "roster_commitment_base64url": b64u(roster_value),
            "topic_binding_base64url": b64u(topic_value),
            "topic_key_epoch": topic_key_epoch,
            "topic_key_epoch_boundary_ms": boundary_ms,
            "tuple_commitment_base64url": b64u(tuple_value),
        },
        "keyset": signed_vector(keyset, keyset_canonical, keyset_input),
        "online_signer_rotation": {
            "activation_at": wire_time(control_activation_at),
            "cutover_keyset": signed_vector(
                keyset_cutover,
                keyset_cutover_canonical,
                keyset_cutover_input,
            ),
            "transition_keyset": signed_vector(
                keyset_transition,
                keyset_transition_canonical,
                keyset_transition_input,
            ),
        },
        "topic_epoch_boundary": {
            "boundary_at": wire_time(boundary_at),
            "new_epoch_assertion": signed_vector(
                new_boundary_assertion,
                new_boundary_assertion_canonical,
                new_boundary_assertion_input,
            ),
            "old_epoch_assertion": signed_vector(
                old_boundary_assertion,
                old_boundary_assertion_canonical,
                old_boundary_assertion_input,
            ),
            "transition_keyset": signed_vector(
                topic_transition_keyset,
                topic_transition_keyset_canonical,
                topic_transition_keyset_input,
            ),
        },
        "assertion": {
            **signed_vector(assertion, assertion_canonical, assertion_input),
            "assertion_hash_base64url": assertion_hash,
        },
        "control_upsert": signed_vector(control, control_canonical, control_input),
        "watermark_current": signed_vector(
            watermark,
            watermark_canonical,
            watermark_input,
        ),
        "subscription_replace": {
            "value": subscription_request,
            "canonical_body_utf8": subscription_canonical.decode("ascii"),
            "canonical_body_sha256": lowerhex_sha256(subscription_canonical),
        },
        "service_jwt": subscription_service_jwt,
        "control_apply_service_jwt": control_service_jwt,
        "watermark_apply_service_jwt": watermark_service_jwt,
        "vault_cas_result": result,
        "pre_egress": {
            "a9_verdict": "ELIGIBLE",
            "effective_deadline": wire_time(expires_at - timedelta(seconds=2)),
            "gate6_independent_fixture_verdict": "VALID",
            "welcome_authorized": False,
        },
    }


def build_negative(positive: dict[str, Any]) -> dict[str, Any]:
    assertion = positive["assertion"]["value"]
    control = positive["control_upsert"]["value"]
    watermark = positive["watermark_current"]["value"]
    request = positive["subscription_replace"]["value"]
    jwt_claims = positive["service_jwt"]["claims"]
    source_tuple = positive["source_tuple"]

    signature_mutated = mutate_b64u_byte(assertion["signature_base64url"])
    topic_mutated = mutate_b64u_byte(assertion["topic_binding"])
    roster_mutated = mutate_b64u_byte(assertion["roster_commitment"])
    tuple_mutated = mutate_b64u_byte(assertion["tuple_commitment"])
    assertion_hash_mutated = mutate_b64u_byte(positive["assertion"]["assertion_hash_base64url"])
    topic_bytes = bytes.fromhex(positive["topic_resolver"]["topic_bytes_hex"])
    transport_conversation_id = request["subscriptions"][0]["transport_conversation_id"]
    transport_mutated = transport_conversation_id[:-1] + (
        "0" if transport_conversation_id[-1] != "0" else "1"
    )
    transition_keyset = positive["online_signer_rotation"]["transition_keyset"]["value"]
    cutover_keyset = positive["online_signer_rotation"]["cutover_keyset"]["value"]
    next_control_signing_key_id = positive["test_keys"]["next_control_signing_key_id"]
    control_signing_key_id = positive["test_keys"]["control_signing_key_id"]
    next_control_key = next(
        key for key in transition_keyset["keys"] if key["key_id"] == next_control_signing_key_id
    )
    expired_control_key = next(
        key for key in cutover_keyset["keys"] if key["key_id"] == control_signing_key_id
    )
    subscription_topic_bindings = [
        request["subscriptions"][0]["topic_binding"],
        positive["topic_epoch_boundary"]["new_epoch_assertion"]["value"]["topic_binding"],
    ]
    subscription_topic_bindings.sort(
        key=lambda value: base64.urlsafe_b64decode(value + ("=" * (-len(value) % 4)))
    )
    duplicate_raw = (
        '{"protocol":"hytch.a9-bridge-assertion","protocol":"hytch.a9-bridge-assertion"}'
    )

    vectors = [
        {
            "id": "assertion_signature_one_byte",
            "base": "positive.assertion.value",
            "mutation": {
                "op": "replace",
                "path": "/signature_base64url",
                "value": signature_mutated,
            },
            "expected": {"terminal": "INVALID", "reason": "BAD_SIGNATURE"},
        },
        {
            "id": "wrong_signature_domain",
            "base": "positive.assertion.value",
            "mutation": {
                "verification_domain_utf8": CONTROL_DOMAIN.decode("ascii"),
            },
            "expected": {"terminal": "INVALID", "reason": "BAD_SIGNATURE"},
        },
        {
            "id": "assertion_unsigned_one_byte",
            "base": "positive.assertion.value",
            "mutation": {
                "op": "replace",
                "path": "/state",
                "value": "REVOKED",
            },
            "expected": {"terminal": "INVALID", "reason": "FIELD_DOMAIN"},
        },
        {
            "id": "duplicate_json_key",
            "base": "raw",
            "mutation": {"raw_utf8": duplicate_raw},
            "expected": {"terminal": "INVALID", "reason": "DUPLICATE_KEY"},
        },
        {
            "id": "unknown_assertion_field",
            "base": "positive.assertion.value",
            "mutation": {
                "op": "add",
                "path": "/roster_digest",
                "value": source_tuple["roster_digest_base64url"],
            },
            "expected": {
                "terminal": "INVALID",
                "reason": "UNKNOWN_FIELD_RAW_ROSTER_FORBIDDEN",
            },
        },
        {
            "id": "padded_signature",
            "base": "positive.assertion.value",
            "mutation": {
                "op": "replace",
                "path": "/signature_base64url",
                "value": assertion["signature_base64url"] + "==",
            },
            "expected": {"terminal": "INVALID", "reason": "NONCANONICAL_BASE64URL"},
        },
        {
            "id": "wrong_length_base64url",
            "base": "positive.assertion.value",
            "mutation": {
                "op": "replace",
                "path": "/binding_id",
                "value": assertion["binding_id"][:-1],
            },
            "expected": {"terminal": "INVALID", "reason": "NONCANONICAL_BASE64URL"},
        },
        {
            "id": "noncanonical_uuid",
            "base": "positive.subscription_replace.value",
            "mutation": {
                "op": "replace",
                "path": "/account_incarnation_id",
                "value": request["account_incarnation_id"].upper(),
            },
            "expected": {"terminal": "INVALID", "reason": "FIELD_DOMAIN"},
        },
        {
            "id": "wrong_environment_spelling",
            "base": "positive.assertion.value",
            "mutation": {
                "op": "replace",
                "path": "/environment",
                "value": "development",
            },
            "expected": {"terminal": "INVALID", "reason": "FIELD_DOMAIN"},
        },
        {
            "id": "wrong_audience",
            "base": "positive.assertion.value",
            "mutation": {
                "op": "replace",
                "path": "/audience",
                "value": "hytch.xmtp-push-bridge.welcome",
            },
            "expected": {"terminal": "INVALID", "reason": "WRONG_AUDIENCE"},
        },
        {
            "id": "welcome_purpose",
            "base": "positive.assertion.value",
            "mutation": {
                "op": "replace",
                "path": "/purpose",
                "value": "welcome_push",
            },
            "expected": {"terminal": "INVALID", "reason": "WELCOME_CLOSED"},
        },
        {
            "id": "noncanonical_timestamp",
            "base": "positive.assertion.value",
            "mutation": {
                "op": "replace",
                "path": "/issued_at",
                "value": "2026-07-29T17:00:00Z",
            },
            "expected": {"terminal": "INVALID", "reason": "NONCANONICAL_TIME"},
        },
        {
            "id": "integer_as_float",
            "base": "positive.assertion.value",
            "mutation": {
                "op": "replace",
                "path": "/binding_version",
                "value": 4.0,
            },
            "expected": {"terminal": "INVALID", "reason": "NON_IJSON_NUMBER"},
        },
        {
            "id": "integer_overflow",
            "base": "positive.assertion.value",
            "mutation": {
                "op": "replace",
                "path": "/stream_sequence",
                "value": MAX_IJSON_INTEGER + 1,
            },
            "expected": {"terminal": "INVALID", "reason": "INTEGER_RANGE"},
        },
        {
            "id": "wrong_topic_binding",
            "base": "positive.assertion.value",
            "mutation": {
                "op": "replace",
                "path": "/topic_binding",
                "value": topic_mutated,
            },
            "expected": {"terminal": "INVALID", "reason": "TOPIC_BINDING_MISMATCH"},
        },
        {
            "id": "wrong_roster_commitment",
            "base": "positive.assertion.value",
            "mutation": {
                "op": "replace",
                "path": "/roster_commitment",
                "value": roster_mutated,
            },
            "expected": {"terminal": "INVALID", "reason": "ROSTER_COMMITMENT_MISMATCH"},
        },
        {
            "id": "wrong_tuple_commitment",
            "base": "positive.assertion.value",
            "mutation": {
                "op": "replace",
                "path": "/tuple_commitment",
                "value": tuple_mutated,
            },
            "expected": {
                "terminal": "INVALID",
                "reason": "TUPLE_COMMITMENT_MISMATCH",
            },
        },
        {
            "id": "tuple_source_account_mutation",
            "base": "positive.source_tuple + positive.assertion.value",
            "mutation": {
                "op": "replace",
                "path": "/source_tuple/account_incarnation_id",
                "value": "2bf32592-a919-43b3-9360-d1fd360df82b",
            },
            "expected": {
                "terminal": "INVALID",
                "reason": "TUPLE_COMMITMENT_MISMATCH",
            },
        },
        {
            "id": "stale_topic_key_epoch",
            "base": "positive.assertion.value",
            "mutation": {
                "op": "replace",
                "path": "/topic_key_epoch",
                "value": assertion["topic_key_epoch"] - 2,
            },
            "expected": {"terminal": "INVALID", "reason": "TOPIC_KEY_EPOCH"},
        },
        {
            "id": "unknown_signer",
            "base": "positive.assertion.value",
            "mutation": {
                "op": "replace",
                "path": "/signing_key_id",
                "value": "ed25519-sha256:" + ("0" * 64),
            },
            "expected": {"terminal": "INVALID", "reason": "KEY_STATE"},
        },
        {
            "id": "signer_not_yet_valid",
            "base": "positive.online_signer_rotation.transition_keyset.value",
            "mutation": {
                "signing_key_id": next_control_key["key_id"],
                "evaluation_time": transition_keyset["issued_at"],
            },
            "expected": {"terminal": "INVALID", "reason": "KEY_STATE"},
        },
        {
            "id": "signer_expired",
            "base": "positive.online_signer_rotation.cutover_keyset.value",
            "mutation": {
                "signing_key_id": expired_control_key["key_id"],
                "evaluation_time": expired_control_key["not_after"],
            },
            "expected": {"terminal": "INVALID", "reason": "KEY_STATE"},
        },
        {
            "id": "expired_assertion",
            "base": "positive.assertion.value",
            "mutation": {"evaluation_time": assertion["expires_at"]},
            "expected": {"terminal": "INVALID", "reason": "EXPIRED"},
        },
        {
            "id": "control_upsert_shape_mismatch",
            "base": "positive.control_upsert.value",
            "mutation": {
                "op": "replace",
                "path": "/reason_code",
                "value": "authority_revoked",
            },
            "expected": {"terminal": "INVALID", "reason": "FIELD_DOMAIN"},
        },
        {
            "id": "control_gap_upsert",
            "base": "positive.control_upsert.value",
            "mutation": {"bridge_applied_sequence": control["expected_previous_sequence"] - 1},
            "expected": {"terminal": "INCONCLUSIVE", "reason": "CONTROL_GAP"},
        },
        {
            "id": "control_sequence_regression",
            "base": "positive.control_upsert.value",
            "mutation": {
                "bridge_applied_sequence": control["stream_sequence"] + 1,
            },
            "expected": {
                "terminal": "STALE",
                "reason": "CONTROL_SEQUENCE_REGRESSION",
            },
        },
        {
            "id": "revoke_across_gap",
            "base": "positive.control_upsert.value",
            "mutation": {
                "action": "REVOKE",
                "assertion": None,
                "reason_code": "authority_revoked",
                "bridge_applied_sequence": 2,
            },
            "expected": {
                "terminal": "REVOKED",
                "reason": "DENY_APPLIES_AND_UNCERTAINTY_LATCHES",
            },
        },
        {
            "id": "idempotency_key_different_body",
            "base": "positive.control_upsert.value",
            "mutation": {"same_idempotency_key": True, "body_changed": True},
            "expected": {
                "terminal": "INCONCLUSIVE",
                "reason": "IDEMPOTENCY_CONFLICT",
            },
        },
        {
            "id": "upsert_after_tombstone",
            "base": "positive.control_upsert.value",
            "mutation": {"binding_tombstoned": True},
            "expected": {"terminal": "REVOKED", "reason": "TOMBSTONE_WINS"},
        },
        {
            "id": "revoke_refresh_race",
            "base": "positive.subscription_replace.value",
            "mutation": {
                "concurrent_revoke": {
                    "assertion_hash": control["assertion_hash"],
                    "binding_id": control["binding_id"],
                    "binding_version": control["binding_version"],
                    "stream_sequence": control["stream_sequence"] + 1,
                },
            },
            "expected": {"terminal": "REVOKED", "reason": "TOMBSTONE_WINS"},
        },
        {
            "id": "watermark_expired",
            "base": "positive.watermark_current.value",
            "mutation": {"evaluation_time": watermark["expires_at"]},
            "expected": {"terminal": "INCONCLUSIVE", "reason": "WATERMARK_EXPIRED"},
        },
        {
            "id": "watermark_max_seen_with_gap",
            "base": "positive.watermark_current.value",
            "mutation": {
                "applied_sequences": [1, 2, 4, 5, 6, 7],
                "committed_through_stream_sequence": 7,
            },
            "expected": {"terminal": "INCONCLUSIVE", "reason": "WATERMARK_GAP"},
        },
        {
            "id": "watermark_sequence_rollback",
            "base": "positive.watermark_current.value",
            "mutation": {
                "stored_watermark_sequence": watermark["watermark_sequence"] + 1,
            },
            "expected": {
                "terminal": "INCONCLUSIVE",
                "reason": "WATERMARK_ROLLBACK",
            },
        },
        {
            "id": "watermark_uncertain",
            "base": "positive.watermark_current.value",
            "mutation": {
                "status": "UNCERTAIN",
                "uncertainty_reason": "SOURCE_UNAVAILABLE",
            },
            "expected": {"terminal": "INCONCLUSIVE", "reason": "SOURCE_UNAVAILABLE"},
        },
        {
            "id": "sequencer_epoch_change",
            "base": "positive.watermark_current.value",
            "mutation": {"sequencer_epoch": b64u(bytes(reversed(range(48, 64))))},
            "expected": {"terminal": "INCONCLUSIVE", "reason": "EPOCH_MISMATCH"},
        },
        {
            "id": "restart_ambiguity",
            "base": "bridge_state",
            "mutation": {"durable_applied_cursor_available": False},
            "expected": {"terminal": "INCONCLUSIVE", "reason": "REPLICA_AMBIGUITY"},
        },
        {
            "id": "cross_installation_assertion",
            "base": "positive.subscription_replace.value",
            "mutation": {
                "op": "replace",
                "path": "/installation_binding_id",
                "value": b64u(bytes(range(1, 17))),
            },
            "expected": {"terminal": "INVALID", "reason": "INSTALLATION_MISMATCH"},
        },
        {
            "id": "cross_topic_assertion_hash",
            "base": "positive.subscription_replace.value",
            "mutation": {
                "op": "replace",
                "path": "/subscriptions/0/assertion_hash",
                "value": assertion_hash_mutated,
            },
            "expected": {"terminal": "INVALID", "reason": "ASSERTION_HASH_MISMATCH"},
        },
        {
            "id": "noncanonical_transport_id_uppercase",
            "base": "positive.subscription_replace.value",
            "mutation": {
                "op": "replace",
                "path": "/subscriptions/0/transport_conversation_id",
                "value": request["subscriptions"][0]["transport_conversation_id"].upper(),
            },
            "expected": {"terminal": "INVALID", "reason": "TOPIC_RESOLVER"},
        },
        {
            "id": "topic_wrong_length",
            "base": "positive.subscription_replace.value",
            "mutation": {
                "op": "replace",
                "path": "/subscriptions/0/topic_base64url",
                "value": b64u(topic_bytes[:-1]),
            },
            "expected": {"terminal": "INVALID", "reason": "TOPIC_RESOLVER"},
        },
        {
            "id": "transport_topic_mismatch",
            "base": "positive.subscription_replace.value",
            "mutation": {
                "op": "replace",
                "path": "/subscriptions/0/transport_conversation_id",
                "value": transport_mutated,
            },
            "expected": {"terminal": "INVALID", "reason": "TOPIC_RESOLVER"},
        },
        {
            "id": "welcome_topic_kind",
            "base": "positive.subscription_replace.value",
            "mutation": {
                "op": "replace",
                "path": "/subscriptions/0/topic_base64url",
                "value": b64u(
                    b"\x01"
                    + bytes.fromhex(request["subscriptions"][0]["transport_conversation_id"])
                ),
            },
            "expected": {"terminal": "INVALID", "reason": "WELCOME_CLOSED"},
        },
        {
            "id": "sender_hmac_period_duplicate",
            "base": "positive.subscription_replace.value",
            "mutation": {"duplicate_hmac_period": True},
            "expected": {"terminal": "INVALID", "reason": "HMAC_PERIOD_DUPLICATE"},
        },
        {
            "id": "duplicate_subscription",
            "base": "positive.subscription_replace.value",
            "mutation": {
                "op": "add",
                "path": "/subscriptions/1",
                "value": request["subscriptions"][0],
            },
            "expected": {
                "terminal": "INVALID",
                "reason": "DUPLICATE_SUBSCRIPTION",
            },
        },
        {
            "id": "unsorted_subscriptions",
            "base": ("individually-valid positive subscriptions ordered by decoded topic_binding"),
            "mutation": {
                "op": "reverse",
                "path": "/subscriptions",
                "submitted_topic_binding_order": list(reversed(subscription_topic_bindings)),
            },
            "expected": {"terminal": "INVALID", "reason": "SUBSCRIPTION_ORDER"},
        },
        {
            "id": "route_key_epoch_rollback",
            "base": "positive.subscription_replace.value",
            "mutation": {"stored_route_key_epoch": 6},
            "expected": {"terminal": "STALE", "reason": "ROUTE_KEY_EPOCH"},
        },
        {
            "id": "partial_cas_failure",
            "base": "positive.subscription_replace.value",
            "mutation": {"fail_after_validating_entry": 0},
            "expected": {
                "terminal": "INCONCLUSIVE",
                "reason": "ATOMIC_ROLLBACK_NO_CHANGE",
            },
        },
        {
            "id": "vault_commit_ambiguous",
            "base": "positive.subscription_replace.value",
            "mutation": {"vault_commit_outcome": "AMBIGUOUS"},
            "expected": {
                "terminal": "INCONCLUSIVE",
                "reason": "VAULT_COMMIT_AMBIGUOUS",
            },
        },
        {
            "id": "jwt_wrong_audience",
            "base": "positive.service_jwt",
            "mutation": {
                "op": "replace",
                "path": "/claims/aud",
                "value": "hytch.xmtp-push-bridge.welcome",
            },
            "expected": {"terminal": "INVALID", "reason": "SERVICE_AUTH"},
        },
        {
            "id": "jwt_wrong_path",
            "base": "positive.service_jwt",
            "mutation": {
                "op": "replace",
                "path": "/claims/path",
                "value": "/internal/v1/xmtp-push/welcomes:authorize",
            },
            "expected": {"terminal": "INVALID", "reason": "SERVICE_AUTH"},
        },
        {
            "id": "jwt_wrong_body_hash",
            "base": "positive.service_jwt",
            "mutation": {
                "op": "replace",
                "path": "/claims/request_sha256",
                "value": "0" * 64,
            },
            "expected": {"terminal": "INVALID", "reason": "SERVICE_AUTH"},
        },
        {
            "id": "jwt_reused_jti",
            "base": "positive.service_jwt",
            "mutation": {"jti_already_consumed": jwt_claims["jti"]},
            "expected": {"terminal": "INVALID", "reason": "SERVICE_AUTH_REPLAY"},
        },
        {
            "id": "keyset_sequence_rollback",
            "base": "positive.keyset.value",
            "mutation": {"stored_keyset_sequence": 18},
            "expected": {"terminal": "INCONCLUSIVE", "reason": "KEYSET_ROLLBACK"},
        },
        {
            "id": "gate6_independent_deny",
            "base": "positive.pre_egress",
            "mutation": {"gate6_independent_fixture_verdict": "DENY"},
            "expected": {"terminal": "INCONCLUSIVE", "reason": "GATE6_DENY"},
        },
    ]
    return {
        "contract": "hytch.xmtp-push.a9-adapter.v1",
        "rule": (
            "Every vector is terminal. INVALID, STALE, REVOKED, and "
            "INCONCLUSIVE always produce zero egress; none maps to valid zero."
        ),
        "vectors": vectors,
    }


def build_outputs() -> dict[Path, bytes]:
    positive = build_positive()
    negative = build_negative(positive)
    positive_bytes = pretty_json(positive)
    negative_bytes = pretty_json(negative)
    manifest = {
        "contract": "hytch.xmtp-push.a9-adapter.v1",
        "generated_by": "generate_vectors.py",
        "negative_vector_count": len(negative["vectors"]),
        "positive_sha256": lowerhex_sha256(positive_bytes),
        "negative_sha256": lowerhex_sha256(negative_bytes),
        "schema_dialect": "https://json-schema.org/draft/2020-12/schema",
        "terminal_verdicts": [
            "ELIGIBLE",
            "INVALID",
            "STALE",
            "REVOKED",
            "INCONCLUSIVE",
        ],
        "welcome": "CLOSED",
    }
    return {
        VECTORS / "positive.json": positive_bytes,
        VECTORS / "negative.json": negative_bytes,
        VECTORS / "manifest.json": pretty_json(manifest),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if committed vectors differ from deterministic output",
    )
    args = parser.parse_args()
    outputs = build_outputs()
    if args.check:
        mismatches: list[str] = []
        for path, expected in outputs.items():
            if not path.exists() or path.read_bytes() != expected:
                mismatches.append(str(path.relative_to(ROOT)))
        if mismatches:
            print("vector drift: " + ", ".join(mismatches), file=sys.stderr)
            return 1
        print("A9 bridge conformance vectors are deterministic and current")
        return 0

    VECTORS.mkdir(parents=True, exist_ok=True)
    for path, content in outputs.items():
        path.write_bytes(content)
        print(path.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
