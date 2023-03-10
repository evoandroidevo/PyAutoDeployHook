# PyAutoDeployHook
Python webhook server for running github deploy on push

I made this to be used as a central webhook entry point for my services running on Portainer stacks

## Config
The basic of the config is a yaml formated file with the name of `config.yaml`.

There are two main keys `REPOS` and `GITHUB_SECRET`.

`REPOS` is a list of 3 keys `name`, `webhook`, and `branch`.

```yaml
GITHUB_SECRET: "secret here"
REPOS:
   - name: "repo name here"
     webhook: "webhook url here"
     branch: "branch of the repo you want to accept requests for"
   - name: "second repo name here"
     webhook: "webhook url here"
     branch: "branch of the repo you want to accept requests for"
```
### Config Notes

The repo name is case-sensitive and should match exactly how it is on GitHub

Branch has to be specified cause GitHub sends a webhook request for any branch that gets a push on a repo

## Install

```console
git clone https://github.com/evoandroidevo/PyAutoDeployHook.git
cd  PyAutoDeployHook
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
deactivate
```
Edit webhook.service to have the right path and user

after the edits are done you can test with 

```console
source venv/bin/activate 
gunicorn --workers 3 --bind 0.0.0.0:5000 server:app
```
should get a similer output of 
```console
Ubuntu gunicorn[205852]: [timestamp] [205852] [INFO] Starting gunicorn 20.1.0
Ubuntu gunicorn[205852]: [timestamp] [205852] [INFO] Listening at: http://0.0.0.0:5000 (205852)
Ubuntu gunicorn[205852]: [timestamp] [205852] [INFO] Using worker: sync
Ubuntu gunicorn[205853]: [timestamp] [205853] [INFO] Booting worker with pid: 205853
Ubuntu gunicorn[205854]: [timestamp] [205854] [INFO] Booting worker with pid: 205854
Ubuntu gunicorn[205855]: [timestamp] [205855] [INFO] Booting worker with pid: 205855
```
now you can move the service file to `/etc/systemd/system/` and start it with

```console
sudo mv webhook.service /etc/systemd/system/pyserver.service
sudo systemctl start pyserver
```
check with `sudo systemctl status webhook` should look something like
```console
* webhook.service - Gunicorn instance to serve webhook listiner
     Loaded: loaded (/etc/systemd/system/webhook.service; enabled; vendor preset: enabled)
     Active: active (running) since Fri 2022-11-25 03:27:56 UTC; 25min ago
   Main PID: 205852 (gunicorn)
      Tasks: 4 (limit: 77000)
     Memory: 64.7M
        CPU: 553ms
     CGroup: /system.slice/webhook.service
             |-205852 /usr/webhook/venv/bin/python3 /usr/webhook/venv/bin/gunicorn --workers 3 --bind 0.0.0.0:5000 wsgi:app
             |-205853 /usr/webhook/venv/bin/python3 /usr/webhook/venv/bin/gunicorn --workers 3 --bind 0.0.0.0:5000 wsgi:app
             |-205854 /usr/webhook/venv/bin/python3 /usr/webhook/venv/bin/gunicorn --workers 3 --bind 0.0.0.0:5000 wsgi:app
             `-205855 /usr/webhook/venv/bin/python3 /usr/webhook/venv/bin/gunicorn --workers 3 --bind 0.0.0.0:5000 wsgi:app
```
enable the service at boot with `sudo systemctl enable webhook`

webhooks can now be sent to `0.0.0.0:5000/deploy/` for you GitHub repos 