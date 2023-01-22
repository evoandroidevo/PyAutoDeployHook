import threading
import http.client as httplib
import functools
from flask import Flask, request, abort
import requests
import hmac
import hashlib
import subprocess
import datetime

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

def getHeader(key):
    """Return message header"""

    try:
        return request.headers[key]
    except KeyError:
        abort(400, "Missing header: " + key)

def pullGit(path):
    # process = subprocess.Popen(["git", "pull", "-C", path], stdout=subprocess.PIPE)
    # output = process.communicate()[0]
    sttime = datetime.now().strftime('%Y%m%d_%H:%M:%S - ')
    f = open("test.log", "a")
    f.write(sttime + path + '\n')
    f.close()
    return

# def threaded(func):
#     #https://stackoverflow.com/questions/67071870/python-make-a-function-always-use-a-thread-without-calling-thread-start
#     """Decorator to automatically launch a function in a thread"""
#     @functools.wraps(func)
#     def wrapper(*args, **kwargs):  # replaces original function...
#         # ...and launches the original in a thread
#         thread = threading.Thread(target=func, args=args, kwargs=kwargs)
#         print("Starting Thread")
#         thread.start()
#         return thread
#     return wrapper

def deploy(gitName, private):
    if not private:
        pullGit(gitName)
        return 'success', 201
    else:
        return 'Erorr', 400

@app.route('/deploy', methods=['POST'])
def webhook():
    """Webhook POST listener"""
    if request.method == 'POST':
        if "GitHub-Hookshot" in _get_header("User-Agent"):
            if verify(secret, request.data, getHeader("X-Hub-Signature-256")):
                repo = request.json.get('repository')
                return deploy(repo.get('name'), repo.get('private'))
            else:
                abort(401)
        else:
            abort(418)
    else:
        abort(405)

if __name__ == '__main__':
    app.run(host="0.0.0.0")