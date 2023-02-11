# TODO add more comments for documentation
import hashlib
import hmac
import http.client as httplib
import logging
import logging.config
import os
import subprocess
import sys
from urllib.parse import urlparse

import requests
import yaml
from flask import Flask, abort, request, Response
from retry import retry

app = Flask(__name__)


class ConfigFileNotFound(Exception):
    pass


class NoInternet(Exception):
    pass


# read logging config for setup and fall back to basicConfig if file not found or has yaml errors
def setup_logging(default_path='logconfig.yaml', default_level=logging.INFO, env_key='LOG_CFG'):
    """
    | **@author:** Prathyush SP
    | Logging Setup
    """
    path = default_path
    value = os.getenv(env_key, None)
    if value:
        path = value
    if os.path.exists(path):
        with open(path, 'rt') as f:
            try:
                config = yaml.safe_load(f.read())
                logging.config.dictConfig(config['LOGS'])
            except Exception as e:
                logging.basicConfig(format='%(asctime)-18s - %(name)-8s - %(levelname)-8s : %(message)s',
                                    datefmt='%m-%d-%Y_%H:%M:%S', filename='webhook.log', level=logging.INFO)
                print(e)
                print('Error in Logging Configuration. Using default configs')
    else:
        logging.basicConfig(format='%(asctime)-18s - %(name)-8s - %(levelname)-8s : %(message)s',
                            datefmt='%m-%d-%Y_%H:%M:%S', filename='webhook.log', level=logging.INFO)
        print('Failed to load configuration file. Using default configs')


# Read config file and throw a ConfigFileNotFound exception if there was an error with the config
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
                logging.error(e)
                print(e)
                print('Error in Loaded Configuration.')
                raise ConfigFileNotFound("Error in Loaded Configuration.")
    else:
        logging.error("Config missing")
        print('Failed to load configuration file.')
        raise ConfigFileNotFound("Config file missing")


yamlconfig = readConfig()

secret = ""


# verify the request with hmac header
def verify(api_key, body, signature):
    key = api_key.encode("utf-8")
    hmac_digest = hmac.new(key, body, digestmod=hashlib.sha256).hexdigest()
    sig_part = signature.split("=", 1)
    fsignature = sig_part[1].encode('utf-8')
    return hmac.compare_digest(fsignature, hmac_digest.encode('utf-8'))


# returns the header value or aborts if the header is missing
def getHeader(key):
    """Return message header"""
    try:
        return request.headers[key]
    except KeyError:
        abort(400, "Missing header: " + key)


# checks for internet access though googles dns server
def have_internet() -> bool:  # https://stackoverflow.com/questions/3764291/how-can-i-see-if-theres-an-available-and-active-network-connection-in-python
    conn = httplib.HTTPSConnection("8.8.8.8", timeout=5)
    try:
        conn.request("HEAD", "/")
        return True
    except Exception:
        return False
    finally:
        conn.close()


# sends the request to the webhook url in config and returns the response to the sender
@retry(NoInternet, delay=5, tries=30, backoff=30, max_delay=120)
def sendWebhook(arg, sendURL):
    # used https://gist.github.com/Bilka2/5dd2ca2b6e9f3573e0c2defe5d3031b2
    # as a base for this.
    try:
        parsed_url = urlparse(sendURL)
        if not all([parsed_url.scheme, parsed_url.netloc]):
            raise Exception("Invalid sendURL")

        if have_internet():
            result = requests.post(sendURL, json=arg)
            if 200 <= result.status_code < 300:
                # print(f"Webhook sent. \nReturned Code: {result.status_code}")
                returnData = f"Webhook sent. \nReturned Code: {result.status_code}"
                return Response(returnData, status=result.status_code)
            else:
                # print(f"Not sent with {result.status_code}, response:\n{result.json()}")
                errorData = f"Not sent with {result.status_code}, response:\n{result.json()}"
                # return errorData, result.status_code
                return Response(errorData, status=result.status_code)
        else:
            raise NoInternet("ERROR: No Internet Detected.")

    except NoInternet as e:
        logging.info("No internet detected")
        logging.debug(e)
        raise
    except Exception as error:
        print(error)
        return Response(f'URL error in config', status=400)


def pullGit(path):
    """Pulls the repo"""
    process = subprocess.Popen(
        ["git", "-C",  "/home/vscode/Code/GithubProjects/" + path + "/", "pull"], stdout=subprocess.PIPE)
    output = process.communicate()[0]
    exitcode = process.returncode
    logging.info("Git output: " + output.decode("utf-8"))
    logging.debug("Git Exitcode is: " + str(exitcode))
    if exitcode == 0:
        return output, 201
    else:
        return 'Git returned an error', 400


# Uses the requests data points and reads the config to route the request to the correct place
def deploy(gitName, branch, data):
    """Deploy logic"""
    repos = yamlconfig['REPOS']
    logging.debug(repos)
    logging.debug(len(repos))
    logging.debug(type(repos))
    logging.debug(branch)
    branch = branch.replace("refs/heads/", "")
    logging.debug(branch)
    y = 0
    for x in repos:
        if branch == x['branch']:
            logging.debug("current branch is " + branch)
            if x['name'] == gitName:
                logging.debug("current repo is " + gitName)
                logging.info("sending request to " + x['webhook'])
                return sendWebhook(data, x['webhook'])
            elif y == len(repos) - 1:
                logging.debug("Checked list spot " + str(y))
                logging.debug("No Repo with name " + gitName +
                              " in config file ignoring request and returning http code 202 ")
                return Response(f'No Repo in config file ingnoring request', status=202)
        elif y == len(repos) - 1:
            logging.debug("Checked list spot " + str(y))
            logging.debug("No Branch with name " + branch +
                          " in config file ignoring request and returning http code 202 ")
            return Response(f'No Branch in config file ignoring request', status=202)
        logging.debug("Checked list spot " + str(y))
        y += 1


# Main section that is used by flask to recive the webhook requests
@app.route('/deploy', methods=['POST'])
def webhook():
    """Webhook POST listener"""
    logging.info("Request recived from " + getHeader('cf-connecting-ip'))
    logging.debug(request.headers)
    logging.debug(request.data)
    if request.method == 'POST':
        if "GitHub-Hookshot" in getHeader("User-Agent"):
            if verify(yamlconfig['GITHUB_SECRET'], request.data, getHeader("X-Hub-Signature-256")):
                logging.info("request verifyed")
                repo = request.json.get('repository')
                return deploy(repo.get('name'), request.json.get('ref'), request.json)
            else:
                abort(401)
        else:
            abort(418)
    else:
        abort(405)


# Starts the server and closes the server if no config is found
if __name__ == '__main__':
    setup_logging()
    logging.info('Starting')
    try:
        app.run(host="0.0.0.0")
    except ConfigFileNotFound as e:
        logging.critical(e)
        sys.exit(1)
    logging.info('Exiting')
