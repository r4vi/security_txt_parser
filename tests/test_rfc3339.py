
import pytest
from abnf import ParseError

from security_txt_parser.grammars import rfc3339

def test_date_fullyear():
    node = rfc3339.Rule('date-fullyear').parse_all("2022")
    assert node and node.value == "2022"

@pytest.mark.parametrize("src, raises", [
    ("2022-01-01T12:00:00Z", False),
    ("2019-10-12T07:20:50.52+00:00", False),
    ("2019-10-12T03:20:50.52-04:00", False),
    ("2019-10-12 03:20:50.52-04:00", True)
])
def test_date_time(src, raises):
    if raises:
        with pytest.raises(ParseError):
            rfc3339.Rule("date-time").parse_all(src)
    else:
        node = rfc3339.Rule("date-time").parse_all(src)
        assert node and node.value == src
