import threading
import http.client as httplib
import functools
from flask import Flask, request, abort
import requests
import hmac
import hashlib
import subprocess

app = Flask(__name__)

secret = ""

def verify(api_key, body, signature):
    key = api_key.encode("utf-8")
    hmac_digest = hmac.new(key,body,digestmod=hashlib.sha256).hexdigest()
    sig_part = signature.split("=", 1)
    fsignature = sig_part[1].encode('utf-8')
    # if isinstance(fsignature, str):
    #     print("fsignature is string", file=sys.stdout)
    # if isinstance(hmac_digest, str):
    #     print("hmac digest is string", file=sys.stdout)
    return hmac.compare_digest(fsignature, hmac_digest.encode('utf-8'))

def _get_header(key):
    """Return message header"""

    try:
        return request.headers[key]
    except KeyError:
        abort(400, "Missing header: " + key)

def threaded(func):
    #https://stackoverflow.com/questions/67071870/python-make-a-function-always-use-a-thread-without-calling-thread-start
    """Decorator to automatically launch a function in a thread"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):  # replaces original function...
        # ...and launches the original in a thread
        thread = threading.Thread(target=func, args=args, kwargs=kwargs)
        print("Starting Thread")
        thread.start()
        return thread
    return wrapper

def deploy():
    
    return None

@app.route('/deploy', methods=['POST'])
def webhook():
    """Webhook POST listener"""
    if request.method == 'POST':
        if "GitHub-Hookshot" in _get_header("User-Agent"):
            if verify(secret, request.data, _get_header("X-Hub-Signature-256")):
                #deploy()
                return 'success', 201
            else:
                abort(401)
        else:
            abort(418)
    else:
        abort(405)

@app.route('/')
def results():
    content = "nothing"
    return '<html><head>custom head stuff here</head><body><br>' + content + '</body></html>'

if __name__ == '__main__':
    app.run(host="0.0.0.0")