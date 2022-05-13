
# Security.txt (rfc9116) parser

A parser for security.txt generated from the ABNF specified in [rfc9116].

Currently a work in progress as the ABNF doesn't seem to parse common samples.





## Run Locally

Clone the project

```bash
  git clone https://github.com/r4vi/security_txt_parser
```

Go to the project directory

```bash
  cd security_txt_parser
```

Install dependencies

this project uses [poetry] to manage dependencies. Ensure you have it installed.

```bash
  poetry install
```

Run the tests

```bash
  poetry run pytest
```

[rfc9116]: https://www.rfc-editor.org/rfc/rfc9116.html#name-file-format-description-and
[poetry]: https://python-poetry.org/docs/#installation
