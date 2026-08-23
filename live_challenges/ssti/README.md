# SSTI (live HTTP)

`http://HOST:PORT/`. `GET /greet?name=<x>` renders your input as a Jinja2
template — `{{7*7}}` returns `49`. Escalate the template injection to code
execution and read the flag from the environment. A filter rejects `.` and the
words the obvious payloads need (`os`, `popen`, `globals`, `class`, `mro`,
`flag`, `import`, ...), so use the standard bypass: reach attributes with
`|attr()` instead of `.`, and build the blocked words by concatenation.
