# TODO add more comments for documentation
import hashlib
import hmac
import http.client as httplib
import logging
import logging.config
import os
import subprocess
import sys

import requests
import yaml
from flask import Flask, abort, request, Response
from retry import retry

app = Flask(__name__)


class ConfigFileNotFound(Exception):
    pass


class NoInternet(Exception):
    pass


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


def verify(api_key, body, signature):
    key = api_key.encode("utf-8")
    hmac_digest = hmac.new(key, body, digestmod=hashlib.sha256).hexdigest()
    sig_part = signature.split("=", 1)
    fsignature = sig_part[1].encode('utf-8')
    return hmac.compare_digest(fsignature, hmac_digest.encode('utf-8'))


def getHeader(key):
    """Return message header"""
    try:
        return request.headers[key]
    except KeyError:
        abort(400, "Missing header: " + key)


def have_internet() -> bool:  # https://stackoverflow.com/questions/3764291/how-can-i-see-if-theres-an-available-and-active-network-connection-in-python
    conn = httplib.HTTPSConnection("8.8.8.8", timeout=5)
    try:
        conn.request("HEAD", "/")
        return True
    except Exception:
        return False
    finally:
        conn.close()


@retry(NoInternet, delay=5, tries=30, backoff=30, max_delay=120)
def sendWebhook(arg, sendURL):
    # used https://gist.github.com/Bilka2/5dd2ca2b6e9f3573e0c2defe5d3031b2
    # as a base for this.
    try:
        # TODO: add catch for webhook url is invalid
        if have_internet():
            result = requests.post(sendURL, json=arg)
            if 200 <= result.status_code < 300:
                # print(f"Webhook sent. \nReturned Code: {result.status_code}")
                returnData = f"Webhook sent. \nReturned Code: {result.status_code}"
                return Response(returnData, status=result.status_code)
            else:
                # print(f"Not sent with {result.status_code}, response:\n{result.json()}")
                errorData = f"Not sent with {result.status_code}, response:\n{result.json()}"
                #return errorData, result.status_code
                return Response(errorData, status=result.status_code)
        else:
            raise NoInternet("ERROR: No Internet Detected.")

    except Exception as error:
        print(error)
        raise


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


def deploy(gitName, private, data):
    # TODO: Add check for branch
    """Deploy logic"""
    repos = yamlconfig['REPOS']
    logging.debug(repos)
    logging.debug(len(repos))
    logging.debug(type(repos))
    y = 0
    for x in repos:
        if x['name'] == gitName:
            logging.debug("current repo is " + gitName)
            logging.info("sending request to " + x['webhook'])
            return sendWebhook("Webhook received and valid", x['webhook'])
        elif y == len(repos):
            return Response(f'Error: No Repo in config file', status=400)
        y += 1


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
                return deploy(repo.get('name'), repo.get('private'), request.json)
            else:
                abort(401)
        else:
            abort(418)
    else:
        abort(405)


if __name__ == '__main__':
    setup_logging()
    logging.info('Starting')
    try:
        app.run(host="0.0.0.0")
    except ConfigFileNotFound as e:
        logging.critical(e)
        sys.exit(1)
    logging.info('Exiting')
