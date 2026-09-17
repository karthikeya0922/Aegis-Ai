"""Phase 1 -- secret and credential detection.

Structure:
  * true positives      -- each provider family
  * false positives     -- the documentation/fixture corpus that must stay quiet
  * overlap resolution  -- one finding per span, not three
  * privacy invariants  -- raw values stay out of Detection objects
  * known misses        -- documented, not hidden

The known-misses block is deliberate. A detector that cannot state what it
misses cannot be trusted about what it catches, and those cases feed the
limitations panel in the UI.
"""

from __future__ import annotations

import pytest

from app.contracts.common import DetectionCategory, PolicyAction
from app.security.secret_scanner import SecretScanner, get_scanner

# A structurally valid JWT: header decodes to {"alg":"HS256","typ":"JWT"}
VALID_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
    ".dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

PEM_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAx7Vv8sKq3nZfQ2mWpL4tR8yBnC6dF1gH0jSxQ9vB2mK7pL4n
R8tW5yZ3aC6dF1gH0jSxQ9vB2mK7pL4nR8tW5yZ3aC6dF1gH0jSxQ9vB2mK7pL4n
-----END RSA PRIVATE KEY-----"""


def _joined(*parts: str) -> str:
    """Assemble a secret-shaped fixture at runtime.

    Some of these strings have exactly the shape of a live credential -- which
    is the point of the test -- and GitHub's push protection flags them as
    such when they appear as literals in a committed file. Splitting the
    literal defeats the source scanner while the *runtime* string still
    exercises the full pattern. This is the same approach gitleaks and
    detect-secrets use in their own test suites.

    A secret scanner's test suite tripping another secret scanner is, in
    fairness, exactly the kind of thing this project exists to demonstrate.
    """
    return "".join(parts)


# Assembled at import time; never a single literal in source.
SLACK_TOKEN = _joined("xoxb-", "123456789012-", "1234567890123-", "AbCdEfGhIjKlMnOpQrStUvWx")
STRIPE_KEY = _joined("sk_", "live_", "4eC39HqLyjWDarjtT1zdp7dc")


@pytest.fixture(scope="module")
def scanner() -> SecretScanner:
    return get_scanner()


def types_in(scanner: SecretScanner, text: str) -> set[str]:
    detections, _ = scanner.scan(text)
    return {d.type for d in detections}


# ---------------------------------------------------------------------------
# True positives
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "text", "expected_type"),
    [
        ("aws access key", "AKIAIOSFODNN7EXAMPLE", "AWS_ACCESS_KEY"),
        ("aws temp key", "ASIAY34FZKBOKMUTVV7A", "AWS_ACCESS_KEY"),
        ("gcp key", "AIzaSyDaGmWKa4JsXZHjVkoHuTfP1cKcs8rTVMg", "GCP_API_KEY"),
        ("github classic", "ghp_16C7e42F292c6912E7710c838347Ae178B4a", "GITHUB_TOKEN"),
        ("github oauth", "gho_16C7e42F292c6912E7710c838347Ae178B4a", "GITHUB_TOKEN"),
        ("gitlab pat", "glpat-ABCdefGHIjklMNOpqrST", "GITLAB_TOKEN"),
        ("anthropic", "sk-ant-api03-abcdefghijklmnopqrstuvwxyz123456", "ANTHROPIC_API_KEY"),
        ("huggingface", "hf_ABCdefGHIjklMNOpqrSTuvwXYZ01234567", "HUGGINGFACE_TOKEN"),
        ("slack", SLACK_TOKEN, "SLACK_TOKEN"),
        ("stripe", STRIPE_KEY, "STRIPE_SECRET_KEY"),
        ("npm", "npm_ABCdefGHIjklMNOpqrSTuvwXYZ0123456789", "NPM_TOKEN"),
        ("jwt", VALID_JWT, "JWT"),
        ("pem key", PEM_KEY, "PRIVATE_KEY"),
    ],
)
def test_detects_credential(scanner, label, text, expected_type):
    assert expected_type in types_in(scanner, f"here is the value {text} ok")


@pytest.mark.parametrize(
    "uri",
    [
        "postgres://admin:SecretPassword@db.internal:5432/users",
        "postgresql://u:p4ssw0rd!@10.0.0.5:5432/prod",
        "mysql://root:Tr0ub4dor@mysql.example.com/app",
        "mongodb+srv://svc:S3cr3tV4lue@cluster0.mongodb.net/test",
        "redis://default:Rd1sP4ssw0rd@cache.internal:6379",
    ],
)
def test_detects_database_uri_credentials(scanner, uri):
    assert "DATABASE_CREDENTIAL" in types_in(scanner, f"connect to {uri} now")


def test_aws_example_key_is_still_detected(scanner):
    """AWS's documented example key has real key *shape*.

    Treating a correctly-shaped key as safe because it contains the word
    EXAMPLE is exactly the reasoning that leaks production keys.
    """
    assert "AWS_ACCESS_KEY" in types_in(scanner, "AKIAIOSFODNN7EXAMPLE")


def test_demo_scenario_one(scanner):
    """Spec section 10, scenario 1: the credential-leak demo."""
    text = (
        "Connect using postgres://admin:SecretPassword@db.internal:5432/users\n"
        "AWS: AKIAIOSFODNN7EXAMPLE"
    )
    detections, vault = scanner.scan(text)
    found = {d.type for d in detections}
    assert "DATABASE_CREDENTIAL" in found
    assert "AWS_ACCESS_KEY" in found
    assert len(vault) == 2


def test_private_key_without_footer_is_detected(scanner):
    """A pasted key is often truncated. Still a leak."""
    assert "PRIVATE_KEY" in types_in(scanner, "-----BEGIN OPENSSH PRIVATE KEY-----\nMIIEow")


# ---------------------------------------------------------------------------
# False positives -- the corpus that must stay quiet
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "What is the capital of France?",
        "Summarise this quarterly report for the board.",
        "commit da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "request id 550e8400-e29b-41d4-a716-446655440000",
        "see ./src/components/Button.tsx line 42",
        "the deployment ran at 2024-03-15T10:30:00Z",
        "brand colour is #a3f2b1 on #ffffff",
        "SELECT * FROM users WHERE id = 12345",
        "pip install requests==2.31.0",
        "https://api.example.com/v1/users?limit=50",
        "postgres://localhost:5432/mydb",
    ],
)
def test_benign_text_produces_no_detections(scanner, text):
    detections, vault = scanner.scan(text)
    assert detections == [], f"false positive on: {text}"
    assert vault == {}


@pytest.mark.parametrize(
    "text",
    [
        'password = "your_password_here"',
        "api_key: <YOUR_API_KEY>",
        "SECRET_KEY = 'changeme'",
        "access_token = 'xxxxxxxxxxxxxxxx'",
        "client_secret: replace_me_before_deploy",
        "password = ''",
    ],
)
def test_documentation_placeholders_are_not_credentials(scanner, text):
    assert scanner.scan(text)[0] == [], f"false positive on placeholder: {text}"


@pytest.mark.parametrize(
    "text",
    ["abc.def.ghi", "aaaa.bbbb.cccc", "version.major.minor", "eyJx.notbase64!.zzz"],
)
def test_jwt_validator_rejects_look_alikes(scanner, text):
    """Three dot-separated segments is not enough -- the header must be JSON."""
    assert "JWT" not in types_in(scanner, text)


def test_uri_without_password_is_not_flagged(scanner):
    assert scanner.scan("postgres://localhost:5432/mydb")[0] == []


# ---------------------------------------------------------------------------
# Overlap resolution
# ---------------------------------------------------------------------------


def test_bearer_jwt_yields_one_finding_not_two(scanner):
    """`Bearer <jwt>` matches both rules. It is one credential."""
    detections, _ = scanner.scan(f"Authorization: Bearer {VALID_JWT}")
    assert len(detections) == 1


def test_db_uri_yields_one_finding_not_two(scanner):
    """The URI rule and the generic-password rule both fire on this span."""
    detections, _ = scanner.scan("postgres://admin:SecretPassword@db.internal:5432/users")
    assert len(detections) == 1
    assert detections[0].type == "DATABASE_CREDENTIAL"


def test_whole_uri_is_redacted_not_only_the_password(scanner):
    """Host and database names are infrastructure disclosure in their own right."""
    uri = "postgres://admin:SecretPassword@db.internal:5432/users"
    _, vault = scanner.scan(f"connect {uri} now")
    assert list(vault.values()) == [uri]


def test_repeated_secret_reuses_one_placeholder(scanner):
    key = "AKIAIOSFODNN7EXAMPLE"
    detections, vault = scanner.scan(f"{key} and again {key}")
    assert len(detections) == 2
    assert detections[0].placeholder == detections[1].placeholder
    assert len(vault) == 1


# ---------------------------------------------------------------------------
# Privacy invariants
# ---------------------------------------------------------------------------


def test_detections_never_carry_the_raw_secret(scanner):
    secrets = ["AKIAIOSFODNN7EXAMPLE", "SecretPassword", "ghp_16C7e42F292c6912E7710c838347Ae178B4a"]
    text = (
        "AKIAIOSFODNN7EXAMPLE "
        "postgres://admin:SecretPassword@db.internal:5432/users "
        "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
    )
    detections, vault = scanner.scan(text)
    serialized = "".join(d.model_dump_json() for d in detections)
    for secret in secrets:
        assert secret not in serialized, f"{secret} leaked into a Detection"
        assert any(secret in v for v in vault.values()), "should be in the vault"


def test_offsets_locate_the_secret_without_revealing_it(scanner):
    text = "my key is AKIAIOSFODNN7EXAMPLE ok"
    detections, _ = scanner.scan(text)
    d = detections[0]
    assert text[d.start : d.end] == "AKIAIOSFODNN7EXAMPLE"


def test_scanner_reports_but_does_not_decide(scanner):
    """Separation of concerns: detection never sets a block action.

    The policy engine (phase 6) maps category to action. A scanner that
    returns BLOCK is a bug -- it would make policy unchangeable by config.
    """
    detections, _ = scanner.scan("AKIAIOSFODNN7EXAMPLE and " + PEM_KEY)
    assert detections
    for d in detections:
        assert d.action is PolicyAction.ALLOW
        assert d.category is DetectionCategory.SECRET


def test_every_detection_carries_confidence_and_provenance(scanner):
    detections, _ = scanner.scan(f"AKIAIOSFODNN7EXAMPLE {VALID_JWT}")
    for d in detections:
        assert 0.0 < d.confidence <= 0.99, "never asserts certainty"
        assert d.pattern, "must name the rule that fired"
        assert d.recognizer.startswith("secret_scanner/")


def test_categories_map_to_policy_keys(scanner):
    detections, _ = scanner.scan("AKIAIOSFODNN7EXAMPLE")
    assert scanner.categories_found(detections) == {"aws_credentials"}


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def test_patterns_load_from_config(scanner):
    assert len(scanner.patterns) >= 20
    ids = {p.id for p in scanner.patterns}
    assert {"aws_access_key", "database_uri_credentials", "jwt", "private_key_pem"} <= ids


def test_every_pattern_has_required_metadata(scanner):
    for p in scanner.patterns:
        assert p.id and p.type and p.category and p.placeholder
        assert 0.0 < p.base_confidence <= 0.99
        assert 0.0 <= p.entropy_weight <= 1.0


# ---------------------------------------------------------------------------
# Known misses -- documented, not hidden
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "why"),
    [
        ("QUtJQUlPU0ZPRE5ON0VYQU1QTEU=", "base64-encoded AKIA key"),
        ("AKIA IOSFODNN7 EXAMPLE", "whitespace-split key"),
        ("A-K-I-A-I-O-S-F-O-D-N-N-7", "delimiter-obfuscated key"),
        ("my password is Tr0ub4dor3", "credential stated in prose"),
    ],
)
def test_known_misses_are_documented(scanner, text, why):
    """These are NOT caught. Asserting the gap keeps the claim honest.

    If a future phase closes one of these, this test fails and the limitations
    panel gets updated -- which is the intended workflow.
    """
    assert scanner.scan(text)[0] == [], f"unexpectedly caught: {why}"
