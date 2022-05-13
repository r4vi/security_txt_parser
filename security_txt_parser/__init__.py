from abnf.parser import Rule as _Rule
from abnf.grammars import rfc5322, rfc3986, rfc5646
from abnf.grammars.misc import load_grammar_rules
from .grammars import rfc3339

@load_grammar_rules([
    ("lang-tag", rfc5646.Rule("Language-Tag")),
    ("date-time", rfc3339.Rule("date-time"))
])
class Rule(_Rule):
    """Rules for rfc9116"""
    grammar = [
    # lang-tag from rfc5645
    # date-time from rfc3339
    ]
