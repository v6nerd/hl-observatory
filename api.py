import re

from https import ssl_observatory
from flask import Flask, jsonify, request, abort

app = Flask('observatory')
re_domain = '^([A-Za-z0-9]\.|[A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9]\.){1,3}[A-Za-z]{2,6}$'

@app.route('/', methods=['GET'])
def GET():
    domain = request.args.get('domain')
    if not re.match(re_domain, domain):
        abort(400)

    result = ssl_observatory.verify_domain(domain)

    return jsonify(result)

def start_server(show_debug=False):
    app.run(debug=show_debug)
