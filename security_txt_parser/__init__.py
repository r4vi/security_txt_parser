from abnf.parser import Rule as _Rule
from abnf.grammars import rfc5322, rfc3986, rfc5646, rfc7230
from abnf.grammars.misc import load_grammar_rules
from security_txt_parser.grammars import rfc3339


@load_grammar_rules(
    [
        ("lang-tag", rfc5646.Rule("Language-Tag")),
        ("date-time", rfc3339.Rule("date-time")),
        ("token", rfc7230.Rule("token")),
        ("uri", rfc3986.Rule("URI")),
        ("field-name", rfc5322.Rule("field-name")),
        ("unstructured", rfc5322.Rule("unstructured")),
    ]
)
class Rule(_Rule):
    """Rules for rfc9116"""

    grammar = [
        "body            =  signed / unsigned",
        "unsigned       =  *line (contact-field eol) *line (expires-field eol) *line [lang-field eol] *line",
        #                      ; order of fields within the file is not important
        #                      ; except that if contact-field appears more
        #                      ; than once, the order of those indicates
        #                      ; priority (see Section 2.5.3)""",
        # signed is the production that should match the OpenPGP clearsigned
        # document
        "signed         =  cleartext-header 1*(hash-header) CRLF cleartext signature",
        'cleartext-header =  %s"-----BEGIN PGP SIGNED MESSAGE-----" CRLF',
        'hash-header      =  %s"Hash: " hash-alg *("," hash-alg) CRLF',
        "hash-alg       =  token",
        # ; imported from RFC 2045; see RFC 4880 Section
        # ; 10.3.3 for a pointer to the registry of
        # ; valid values
        # """;cleartext       =  1*( UTF8-octets [CR] LF)
        #                      ; dash-escaped per RFC 4880 Section 7.1
        "cleartext        =  *((line-dash / line-from / line-nodash) [CR] LF)",
        'line-dash        =  ("- ") "-" *UTF8-char-not-cr ; MUST include initial "- "',
        'line-from        =  ["- "] "From " *UTF8-char-not-cr ; SHOULD include initial "- "',
        'line-nodash      =  ["- "] *UTF8-char-not-cr ; MAY include initial "- "',
        "UTF8-char-not-dash =  UTF8-1-not-dash / UTF8-2 / UTF8-3 / UTF8-4",
        "UTF8-1-not-dash  =  %x00-2C / %x2E-7F",
        "UTF8-char-not-cr =  UTF8-1-not-cr / UTF8-2 / UTF8-3 / UTF8-4",
        "UTF8-1-not-cr    =  %x00-0C / %x0E-7F",
        # UTF8 rules from RFC 3629
        "UTF8-octets      =  *( UTF8-char )",
        "UTF8-char        =  UTF8-1 / UTF8-2 / UTF8-3 / UTF8-4",
        "UTF8-1           =  %x00-7F",
        "UTF8-2           =  %xC2-DF UTF8-tail",
        "UTF8-3           =  %xE0 %xA0-BF UTF8-tail / %xE1-EC 2( UTF8-tail ) / %xED %x80-9F UTF8-tail / %xEE-EF 2( UTF8-tail )",
        "UTF8-4           =  %xF0 %x90-BF 2( UTF8-tail ) / %xF1-F3 3( UTF8-tail ) / %xF4 %x80-8F 2( UTF8-tail )",
        "UTF8-tail        =  %x80-BF",
        "signature        =  armor-header armor-keys CRLF signature-data armor-tail",
        'armor-header     =  %s"-----BEGIN PGP SIGNATURE-----" CRLF',
        'armor-keys       =  *(token ": " *( VCHAR / WSP ) CRLF) ; Armor Header Keys from RFC 4880',
        'armor-tail       =  %s"-----END PGP SIGNATURE-----" CRLF',
        """signature-data =  1*(1*(ALPHA / DIGIT / "=" / "+" / "/") CRLF) ; base64; see RFC 4648 ; includes RFC 4880 checksum""",
        "line             =  [ (field / comment) ] eol",
        "eol              =  *WSP [CR] LF",
        """field          = ack-field / can-field / contact-field / encryption-field / hiring-field / policy-field / ext-field""",
        'fs               =  ":"',
        'comment          =  "#" *(WSP / VCHAR / %x80-FFFFF)',
        'ack-field        =  "Acknowledgments" fs SP uri',
        'can-field        =  "Canonical" fs SP uri',
        'contact-field    =  "Contact" fs SP uri',
        'expires-field    =  "Expires" fs SP date-time',
        'encryption-field =  "Encryption" fs SP uri',
        'hiring-field     =  "Hiring" fs SP uri',
        'lang-field       =  "Preferred-Languages" fs SP lang-values',
        'policy-field     =  "Policy" fs SP uri',
        # date-time from [RFC3339], section 5.6
        # lang-tag from [RFC5645] section 2.1
        'lang-values      =  lang-tag *(*WSP "," *WSP lang-tag)',
        # uri              =  < URI as per Section 3 of [RFC3986] >,
        "ext-field        =  field-name fs SP unstructured",
        # field-name       =  < imported from Section 3.6.8 of [RFC5322] >
        # unstructured     =  < imported from Section 3.2.5 of [RFC5322] >
        # token            =  < imported from Section 5.1 of [RFC2045] >
        #                     token from [RFC2045], substituted with token from [RFC7230] which is
        #                     the same thing without validating value is registered with IANA
        "LWSP             =  *(WSP / CRLF WSP)",
        "WSP              =  SP / HTAB",
    ]
