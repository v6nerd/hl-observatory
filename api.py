from flask import Flask, jsonify

app = Flask('observatory')

@app.route('/')
def GET():
    return "home"

def POST():
    return "home"

def start_server(show_debug=False):
    app.run(debug=show_debug)
