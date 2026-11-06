"""Fast checks of the pure-Python helpers: python tests/test_helpers.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cvss import base_score  # noqa: E402
from depparse import locked_to_affected, parse_requirement  # noqa: E402

# Published reference scores from the FIRST CVSS v3.1 calculator.
for vector, expected in [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
    ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N", 0.0),
]:
    assert base_score(vector) == expected, (vector, base_score(vector))
assert base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") is None
assert base_score("garbage") is None

r = parse_requirement('Requests[socks] (>=2.0,<3); python_version >= "3.8"')
assert (r["dst"], r["is_optional"], r["is_conditional"]) == ("requests", False, True), r
assert ">=2.0" in r["spec"] and "<3" in r["spec"]
r = parse_requirement('PySocks!=1.5.7,>=1.5.6; extra == "socks"')
assert (r["dst"], r["is_optional"]) == ("pysocks", True), r
assert parse_requirement("???")["dst"] is None

releases = ["1.0", "1.1", "2.0", "2.1"]
affected = {"1.0", "1.1", "2.0"}
assert locked_to_affected("<2.1", releases, affected) is True      # only affected versions fit
assert locked_to_affected("==1.1", releases, affected) is True
assert locked_to_affected(">=1.0", releases, affected) is False    # 2.1 is reachable
assert locked_to_affected("", releases, affected) is False         # no constraint at all
assert locked_to_affected("not a spec", releases, affected) is None
assert locked_to_affected(">=9", releases, affected) is False      # nothing fits, so no affected install

print("all helper checks passed")
