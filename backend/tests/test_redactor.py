"""Phase 5 -- redaction and vault mapping.

The redactor is the only place sanitised text is produced. These tests pin
the guarantees the scanners cannot give on their own: global placeholder
numbering, offset-safe splicing, cross-scanner precedence, and the vault
policy that keeps secrets from ever being rehydrated.
"""

from __future__ import annotations

import pytest

from app.contracts.common import Detection, DetectionCategory, Message, PolicyAction
from app.security.redactor import Redactor, get_redactor, placeholder_prefix


def det(
    type_: str,
    start: int,
    end: int,
    *,
    mi: int = 0,
    placeholder: str = "[X_1]",
    category: DetectionCategory = DetectionCategory.PII,
    confidence: float = 0.9,
) -> Detection:
    return Detection(
        type=type_,
        category=category,
        placeholder=placeholder,
        confidence=confidence,
        start=start,
        end=end,
        message_index=mi,
        action=PolicyAction.ALLOW,
    )


def user(content: str) -> Message:
    return Message(role="user", content=content)


@pytest.fixture
def r() -> Redactor:
    return Redactor(vault_ttl_seconds=300)


# ---------------------------------------------------------------------------
# Placeholder prefix parsing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("ph", "prefix"),
    [("[EMAIL_1]", "EMAIL"), ("[AWS_KEY_12]", "AWS_KEY"), ("[DB_URI_3]", "DB_URI"), ("[PERSON_1]", "PERSON")],
)
def test_prefix_is_extracted(ph, prefix):
    assert placeholder_prefix(ph) == prefix


def test_prefix_falls_back_on_malformed():
    assert placeholder_prefix("nonsense", fallback="EMAIL_ADDRESS") == "EMAIL_ADDRESS"
    assert placeholder_prefix(None, fallback="T") == "T"


# ---------------------------------------------------------------------------
# Splicing
# ---------------------------------------------------------------------------


def test_single_replacement(r):
    msgs = [user("mail john@example.com now")]
    out = r.redact(msgs, [det("EMAIL_ADDRESS", 5, 21, placeholder="[EMAIL_1]")])
    assert out.messages[0].content == "mail [EMAIL_1] now"
    assert out.vault == {"[EMAIL_1]": "john@example.com"}
    assert out.replacements == 1


def test_multiple_spans_in_one_message_keep_offsets_valid(r):
    """Right-to-left splicing: replacing the later span first leaves the
    earlier offsets intact, even though placeholders change the length."""
    text = "a@x.io and b@y.io and c@z.io"
    msgs = [user(text)]
    dets = [
        det("EMAIL_ADDRESS", 0, 6, placeholder="[EMAIL_1]"),
        det("EMAIL_ADDRESS", 11, 17, placeholder="[EMAIL_1]"),
        det("EMAIL_ADDRESS", 22, 28, placeholder="[EMAIL_1]"),
    ]
    out = r.redact(msgs, dets)
    assert out.messages[0].content == "[EMAIL_1] and [EMAIL_2] and [EMAIL_3]"
    assert out.vault == {"[EMAIL_1]": "a@x.io", "[EMAIL_2]": "b@y.io", "[EMAIL_3]": "c@z.io"}


def test_str_replace_would_have_been_wrong(r):
    """A value that also appears inside another token must only be replaced
    at its detected span. This is the case naive str.replace gets wrong."""
    text = "id 555 and phone 555-123-4567"
    msgs = [user(text)]
    out = r.redact(msgs, [det("PHONE_NUMBER", 17, 29, placeholder="[PHONE_1]")])
    assert out.messages[0].content == "id 555 and phone [PHONE_1]"


def test_adjacent_spans(r):
    msgs = [user("a@x.io,b@y.io")]
    out = r.redact(
        msgs,
        [det("EMAIL_ADDRESS", 0, 6, placeholder="[EMAIL_1]"), det("EMAIL_ADDRESS", 7, 13, placeholder="[EMAIL_1]")],
    )
    assert out.messages[0].content == "[EMAIL_1],[EMAIL_2]"


def test_unicode_offsets(r):
    """Code-point offsets, consistent with what the scanners produce."""
    text = "héllo 🙂 mail john@example.com ok"
    start = text.index("john@example.com")
    msgs = [user(text)]
    out = r.redact(msgs, [det("EMAIL_ADDRESS", start, start + 16, placeholder="[EMAIL_1]")])
    assert out.messages[0].content == "héllo 🙂 mail [EMAIL_1] ok"
    assert out.vault["[EMAIL_1]"] == "john@example.com"


def test_untouched_messages_are_passed_through_identically(r):
    msgs = [Message(role="system", content="You are helpful."), user("mail a@x.io")]
    out = r.redact(msgs, [det("EMAIL_ADDRESS", 5, 11, mi=1, placeholder="[EMAIL_1]")])
    assert out.messages[0] == msgs[0]
    assert out.messages[1].content == "mail [EMAIL_1]"
    assert out.messages[1].role == "user"


# ---------------------------------------------------------------------------
# Global numbering
# ---------------------------------------------------------------------------


def test_identical_values_share_one_placeholder(r):
    text = "john@example.com then again john@example.com"
    msgs = [user(text)]
    dets = [
        det("EMAIL_ADDRESS", 0, 16, placeholder="[EMAIL_1]"),
        det("EMAIL_ADDRESS", 28, 44, placeholder="[EMAIL_1]"),
    ]
    out = r.redact(msgs, dets)
    assert out.messages[0].content == "[EMAIL_1] then again [EMAIL_1]"
    assert len(out.vault) == 1


def test_numbering_is_global_across_messages(r):
    """Each scanner restarts at 1 per call. The redactor must not.

    Two different emails in two messages both arrive as [EMAIL_1]; the
    redactor renumbers so the vault does not silently drop one.
    """
    msgs = [user("mail a@x.io"), user("mail b@y.io")]
    dets = [
        det("EMAIL_ADDRESS", 5, 11, mi=0, placeholder="[EMAIL_1]"),
        det("EMAIL_ADDRESS", 5, 11, mi=1, placeholder="[EMAIL_1]"),
    ]
    out = r.redact(msgs, dets)
    assert out.messages[0].content == "mail [EMAIL_1]"
    assert out.messages[1].content == "mail [EMAIL_2]"
    assert out.vault == {"[EMAIL_1]": "a@x.io", "[EMAIL_2]": "b@y.io"}


def test_same_value_across_messages_shares_placeholder(r):
    msgs = [user("mail a@x.io"), user("again a@x.io")]
    dets = [
        det("EMAIL_ADDRESS", 5, 11, mi=0, placeholder="[EMAIL_1]"),
        det("EMAIL_ADDRESS", 6, 12, mi=1, placeholder="[EMAIL_1]"),
    ]
    out = r.redact(msgs, dets)
    assert out.messages[1].content == "again [EMAIL_1]"
    assert len(out.vault) == 1


def test_numbering_is_deterministic_in_document_order(r):
    """Detections arriving out of order still number by position."""
    msgs = [user("a@x.io b@y.io")]
    dets = [
        det("EMAIL_ADDRESS", 7, 13, placeholder="[EMAIL_1]"),  # b first in the list
        det("EMAIL_ADDRESS", 0, 6, placeholder="[EMAIL_1]"),
    ]
    out = r.redact(msgs, dets)
    assert out.vault["[EMAIL_1]"] == "a@x.io"
    assert out.vault["[EMAIL_2]"] == "b@y.io"


def test_different_prefixes_number_independently(r):
    msgs = [user("a@x.io and AKIAIOSFODNN7EXAMPLE")]
    dets = [
        det("EMAIL_ADDRESS", 0, 6, placeholder="[EMAIL_1]"),
        det("AWS_ACCESS_KEY", 11, 31, placeholder="[AWS_KEY_1]", category=DetectionCategory.SECRET),
    ]
    out = r.redact(msgs, dets)
    assert out.messages[0].content == "[EMAIL_1] and [AWS_KEY_1]"


# ---------------------------------------------------------------------------
# Cross-scanner precedence
# ---------------------------------------------------------------------------


def test_pii_inside_secret_span_yields_to_secret(r):
    """The email-shaped fragment of a DB URI is not an email."""
    uri = "postgres://admin:SecretPassword@db.internal:5432/users"
    text = f"connect {uri} now"
    s = text.index(uri)
    msgs = [user(text)]
    dets = [
        det("DATABASE_CREDENTIAL", s, s + len(uri), placeholder="[DB_URI_1]", category=DetectionCategory.SECRET),
        det("EMAIL_ADDRESS", s + 17, s + 43, placeholder="[EMAIL_1]"),  # SecretPassword@db.internal
    ]
    out = r.redact(msgs, dets)
    assert out.messages[0].content == "connect [DB_URI_1] now"
    assert "[EMAIL_1]" not in out.vault
    assert out.dropped_overlaps == 1
    assert [d.type for d in out.detections] == ["DATABASE_CREDENTIAL"]


def test_partial_overlap_longest_wins(r):
    msgs = [user("0123456789")]
    dets = [
        det("A", 0, 6, placeholder="[A_1]", confidence=0.9),
        det("B", 4, 10, placeholder="[B_1]", confidence=0.95),  # same length, higher conf
    ]
    out = r.redact(msgs, dets)
    assert [d.type for d in out.detections] == ["B"]


def test_no_overlap_keeps_both(r):
    msgs = [user("aaaa bbbb")]
    dets = [det("A", 0, 4, placeholder="[A_1]"), det("B", 5, 9, placeholder="[B_1]")]
    out = r.redact(msgs, dets)
    assert out.messages[0].content == "[A_1] [B_1]"


# ---------------------------------------------------------------------------
# Vault policy -- secrets never rehydrate
# ---------------------------------------------------------------------------


def test_vault_policy_never_rehydrates_secrets(r):
    p = r.vault_policy()
    assert "SECRET" in p.never_rehydrate
    assert "PII" in p.rehydrate
    assert p.ttl_seconds == 300


def test_rehydratable_helper():
    pii = det("EMAIL_ADDRESS", 0, 1)
    sec = det("AWS_ACCESS_KEY", 0, 1, category=DetectionCategory.SECRET)
    assert Redactor.rehydratable(pii) is True
    assert Redactor.rehydratable(sec) is False


def test_secret_rehydration_cannot_be_enabled_by_config(monkeypatch):
    """AEGIS_SECRET_REHYDRATION=true is ignored on purpose (spec s3)."""
    from app import config

    monkeypatch.setattr(config.settings, "secret_rehydration", True)
    p = Redactor().vault_policy()
    assert "SECRET" in p.never_rehydrate
    assert "SECRET" not in p.rehydrate


# ---------------------------------------------------------------------------
# Privacy invariants and robustness
# ---------------------------------------------------------------------------


def test_detections_out_never_carry_raw_values(r):
    msgs = [user("mail john@example.com key AKIAIOSFODNN7EXAMPLE")]
    dets = [
        det("EMAIL_ADDRESS", 5, 21, placeholder="[EMAIL_1]"),
        det("AWS_ACCESS_KEY", 26, 46, placeholder="[AWS_KEY_1]", category=DetectionCategory.SECRET),
    ]
    out = r.redact(msgs, dets)
    serialized = "".join(d.model_dump_json() for d in out.detections)
    assert "john@example.com" not in serialized
    assert "AKIAIOSFODNN7EXAMPLE" not in serialized
    assert set(out.vault.values()) == {"john@example.com", "AKIAIOSFODNN7EXAMPLE"}


def test_out_of_range_span_is_skipped_not_crashed(r):
    msgs = [user("short")]
    out = r.redact(msgs, [det("X", 2, 99, placeholder="[X_1]")])
    assert out.messages[0].content == "short"
    assert out.skipped_invalid == 1
    assert out.vault == {}


def test_bad_message_index_is_skipped(r):
    msgs = [user("short")]
    out = r.redact(msgs, [det("X", 0, 2, mi=5, placeholder="[X_1]")])
    assert out.skipped_invalid == 1


def test_detection_without_placeholder_is_passed_through_unredacted(r):
    msgs = [user("hello world")]
    d = det("NOTE", 0, 5, placeholder=None)  # type: ignore[arg-type]
    out = r.redact(msgs, [d])
    assert out.messages[0].content == "hello world"
    assert out.replacements == 0
    assert out.detections == [d]


def test_empty_inputs(r):
    out = r.redact([], [])
    assert out.messages == [] and out.vault == {} and out.replacements == 0
    out2 = r.redact([user("x")], [])
    assert out2.messages[0].content == "x"


def test_singleton():
    assert get_redactor() is get_redactor()


# ---------------------------------------------------------------------------
# End to end through the real scanners
# ---------------------------------------------------------------------------


def test_end_to_end_multi_message_request():
    """Regression for the joined-text bug: two messages, each with its own
    PII, must each be sanitised in place with distinct placeholders."""
    from app.contracts.inspect import InspectRequest
    from app.stubs import stub_inspect

    req = InspectRequest(
        request_id="req_t",
        messages=[
            Message(role="system", content="You are a support assistant."),
            Message(role="user", content="My email is a@example.com"),
            Message(role="assistant", content="Thanks. Anything else?"),
            Message(role="user", content="Also reach me at b@example.com or +1-555-123-4567"),
        ],
    )
    res = stub_inspect(req)
    assert res.decision.value == "SANITIZE"
    assert res.messages[0].content == "You are a support assistant."
    assert res.messages[1].content == "My email is [EMAIL_1]"
    assert res.messages[2].content == "Thanks. Anything else?"
    assert res.messages[3].content == "Also reach me at [EMAIL_2] or [PHONE_1]"
    assert res.vault == {
        "[EMAIL_1]": "a@example.com",
        "[EMAIL_2]": "b@example.com",
        "[PHONE_1]": "+1-555-123-4567",
    }
    assert {d.message_index for d in res.detections.pii} == {1, 3}
    assert any(s.stage == "redactor" for s in res.pipeline)


def test_end_to_end_blocked_request_returns_original_messages():
    from app.contracts.inspect import InspectRequest
    from app.stubs import stub_inspect

    req = InspectRequest(request_id="req_t", messages=[user("key AKIAIOSFODNN7EXAMPLE")])
    res = stub_inspect(req)
    assert res.decision.value == "BLOCK"
    assert res.messages[0].content == "key AKIAIOSFODNN7EXAMPLE"
    assert res.vault == {"[AWS_KEY_1]": "AKIAIOSFODNN7EXAMPLE"}
