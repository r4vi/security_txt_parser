import pytest

from security_txt_parser import Rule as rfc9116


@pytest.mark.xfail
def test_base_template():
    src = """# Our security address\r\nContact: security@example.com\r\nEncryption: https://example.com/pgp-key.txt"""
    node = rfc9116("body").parse_all(src)

    assert node and node.value == src


valid_comments = [
    "# Comment with space prefix",
    "#Comment without space prefix",
    "# Comment with trailing space and prefix ",
    "#Comment with trailing space but no prefix ",
]


@pytest.mark.parametrize(
    "src",
    valid_comments,
)
def test_comment(src):
    node = rfc9116("comment").parse_all(src)
    assert node and node.value == src


valid_fields = [
    ("Contact: mailto:test@example.com", "contact-field"),
    ("Acknowledgments: https://example.com/humans.txt", "ack-field"),
    ("Canonical: https://example.com/.well-known/security.txt", "can-field"),
    ("Encryption: https://example.com/pgp-key.txt", "encryption-field"),
    ("Hiring: https://example.com/jobs", "hiring-field"),
    ("Policy: https://example.com/policy", "policy-field"),
    ("Hello: mum", "ext-field")

]


@pytest.mark.parametrize(
    "src, expected_type",
    valid_fields
)
def test_field(src, expected_type):
    node = rfc9116('field').parse_all(src)
    assert node and node.value == src and node.children[0].name == expected_type

@pytest.mark.parametrize(
    "src",
    [f"{x}\n" for x in valid_comments]
)
def test_line_with_comment(src):
    node = rfc9116('line').parse_all(src)
    assert node and node.value == src

@pytest.mark.xfail
@pytest.mark.parametrize(
    "src",
    [f"{x[0]}\n" for x in valid_fields]
)
def test_line_with_field(src):
    node = rfc9116('line').parse_all(src)
    assert node and node.value == src
