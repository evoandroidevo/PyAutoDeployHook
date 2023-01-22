import threading
import http.client as httplib
import functools
from flask import Flask, request, abort
import requests
import hmac
import hashlib
import subprocess
import logging

app = Flask(__name__)

# logger = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)-18s - %(name)-8s - %(levelname)-8s : %(message)s', datefmt='%m-%d-%Y_%H:%M:%S', filename='test.log', level=logging.INFO)


secret = ""

def verify(api_key, body, signature):
    key = api_key.encode("utf-8")
    hmac_digest = hmac.new(key,body,digestmod=hashlib.sha256).hexdigest()
    sig_part = signature.split("=", 1)
    fsignature = sig_part[1].encode('utf-8')
    return hmac.compare_digest(fsignature, hmac_digest.encode('utf-8'))

def getHeader(key):
    """Return message header"""
    try:
        return request.headers[key]
    except KeyError:
        abort(400, "Missing header: " + key)

def pullGit(path):
    """Pulls the repo"""
    process = subprocess.Popen(["git", "-C",  "/home/vscode/Code/GithubProjects/" + path + "/", "pull"], stdout=subprocess.PIPE)
    output = process.communicate()[0]
    exitcode = process.returncode
    logging.info("Git output: " + output.decode("utf-8"))
    logging.debug("Git Exitcode is: " + str(exitcode))
    if exitcode is 0:
        return output, 201
    else:
        return 'Git returned an error', 400
    return "error", 400

def deploy(gitName, private):
    """Deploy logic"""
    if not private:
        return pullGit(gitName)
    else:
        return 'Private Repository', 400

@app.route('/deploy', methods=['POST'])
def webhook():
    """Webhook POST listener"""
    logging.info("Request recived from " + request.headers.get('cf-connecting-ip'))
    logging.debug(request.headers)
    logging.debug(request.data)
    if request.method == 'POST':
        if "GitHub-Hookshot" in getHeader("User-Agent"):
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
    logging.info('Starting')
    #app.run(host="0.0.0.0")
    logging.info('Exiting')