#TODO add more comments for documentation
import http.client as httplib
import functools
from flask import Flask, request, abort
import requests
import hmac
import hashlib
import subprocess
import logging
import threading
from retry import retry
import yaml
import os

app = Flask(__name__)
logging.basicConfig(format='%(asctime)-18s - %(name)-8s - %(levelname)-8s : %(message)s', datefmt='%m-%d-%Y_%H:%M:%S', filename='test.log', level=logging.INFO)

def readConfig(default_path='config.yaml', env_key='CFG_PTH'):
    path = default_path
    value = os.getenv(env_key, None)
    if value:
        path = value
    if os.path.exists(path):
        with open(path, 'rt') as f:
            try:
                config = yaml.safe_load(f.read())
                return config
            except Exception as e:
                print(e)
                print('Error in Loaded Configuration. Using default configs')
    else:
        print('Failed to load configuration file. Using default configs')


secret = ""

def getURL(repoName):
    #TODO: get url from config
    """Switch statment for webhook urls"""
    match repoName:
        case "":
            return "https://webhook.site/1ba19da1-0195-47ee-97b9-e30f48302177"
        case _:
            return "https://webhook.site/1ba19da1-0195-47ee-97b9-e30f48302177"


def verify(api_key, body, signature):
    #TODO get secret from config

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

class NoInternet(Exception):
    pass

def have_internet() -> bool: #https://stackoverflow.com/questions/3764291/how-can-i-see-if-theres-an-available-and-active-network-connection-in-python
    conn = httplib.HTTPSConnection("8.8.8.8", timeout=5)
    try:
        conn.request("HEAD", "/")
        return True
    except Exception:
        return False
    finally:
        conn.close()

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

#@threaded
@retry(NoInternet, delay=5, tries=30, backoff=30, max_delay=120)
def sendWebhook(arg, sendURL):
    #used https://gist.github.com/Bilka2/5dd2ca2b6e9f3573e0c2defe5d3031b2
    #as a base for this.
    try:
        #TODO: add catch for webhook url is invalid
        if have_internet():
            result = requests.post(sendURL, json=arg)
            if 200 <= result.status_code < 300:
                #print(f"Webhook sent. \nReturned Code: {result.status_code}")
                returnData = f"Webhook sent. \nReturned Code: {result.status_code}"
                return returnData, result.status_code
            else:
                #print(f"Not sent with {result.status_code}, response:\n{result.json()}")
                errorData = f"Not sent with {result.status_code}, response:\n{result.json()}"
                return errorData, result.status_code
        else:
            raise NoInternet("ERROR: No Internet Detected.")
        
    except Exception as error:
        print(error)
        raise

def pullGit(path):
    """Pulls the repo"""
    process = subprocess.Popen(["git", "-C",  "/home/vscode/Code/GithubProjects/" + path + "/", "pull"], stdout=subprocess.PIPE)
    output = process.communicate()[0]
    exitcode = process.returncode
    logging.info("Git output: " + output.decode("utf-8"))
    logging.debug("Git Exitcode is: " + str(exitcode))
    if exitcode == 0:
        return output, 201
    else:
        return 'Git returned an error', 400
    return "error", 400

def deploy(gitName, private, data):
    #TODO: Add check for branch
    """Deploy logic"""
    match gitName:
        case "PyAutoDeployHook":
            return sendWebhook(data, getURL(gitName))
        case "authelia":
            return sendWebhook(data, getURL(gitName))
        case _:
            return "No info", 400

@app.route('/deploy', methods=['POST'])
def webhook():
    """Webhook POST listener"""
    logging.info("Request recived from " + getHeader('cf-connecting-ip'))
    logging.debug(request.headers)
    logging.debug(request.data)
    if request.method == 'POST':
        if "GitHub-Hookshot" in getHeader("User-Agent"):
            if verify(secret, request.data, getHeader("X-Hub-Signature-256")):
                repo = request.json.get('repository')
                return deploy(repo.get('name'), repo.get('private'), request.json)
            else:
                abort(401)
        else:
            abort(418)
    else:
        abort(405)

if __name__ == '__main__':
    logging.info('Starting')
    app.run(host="0.0.0.0")
    logging.info('Exiting')