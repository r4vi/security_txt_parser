from abnf.grammars.misc import load_grammar_rules
from abnf.parser import Rule as _Rule

@load_grammar_rules()
class Rule(_Rule):
    """Rules from rfc3339

    While the prose of rfc3339 does allow the literal T to be substituted
    with a space in the date-time rule, the abnf grammar in the document
    doesn't allow this. This module doesn't edit the grammar to support that.
    """

    grammar = [
        "date-fullyear = 4DIGIT",
        "date-month = 2DIGIT  ; 01-12",
        "date-mday = 2DIGIT  ; 01-28, 01-29, 01-30, 01-31 based on month/year",
        "time-hour       = 2DIGIT  ; 00-23",
        "time-minute     = 2DIGIT  ; 00-59",
        "time-second     = 2DIGIT  ; 00-58, 00-59, 00-60 based on leap second rules""",
        'time-secfrac    = "." 1*DIGIT',
        'time-numoffset  = ("+" / "-") time-hour ":" time-minute',
        'time-offset     = "Z" / time-numoffset',
        'partial-time    = time-hour ":" time-minute ":" time-second [time-secfrac]',
        'full-date       = date-fullyear "-" date-month "-" date-mday',
        "full-time       = partial-time time-offset",
        'date-time       = full-date "T" full-time',
    ]
