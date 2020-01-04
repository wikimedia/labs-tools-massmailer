# -*- coding: utf-8 -*-
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along
# with this program.  If not, see <http://www.gnu.org/licenses/>.

import flask
import os
import yaml
import requests
from flask import request, flash, redirect
from flask_jsonlocale import Locales
import mwoauth
from requests_oauthlib import OAuth1
import pymysql

app = flask.Flask(__name__)
application = app

# Load config
__dir__ = os.path.dirname(__file__)
app.config.update(
    yaml.safe_load(open(os.path.join(__dir__, os.environ.get(
        'FLASK_CONFIG_FILE', 'config.yaml')))))

locales = Locales(app)
_ = locales.get_message

requests.utils.default_user_agent = lambda: "MassMailer (https://tools.wmflabs.org/massmailer; martin.urbanec@wikimedia.cz)"

# Load configuration from YAML file
__dir__ = os.path.dirname(__file__)
app.config.update(
    yaml.safe_load(open(os.path.join(__dir__, 'config.yaml'))))

key = app.config['CONSUMER_KEY']
secret = app.config['CONSUMER_SECRET']


@app.route('/')
def index():
    username = getusername()
    if username is not None:
        return flask.render_template('tool.html', logged=logged(), username=username)
    else:
        return flask.render_template('login.html', logged=logged(), username=username)


@app.route('/storemails', methods=['POST'])
def storemails():
    users = request.form['users']
    subject = request.form['subject']
    text = request.form['text']
    wiki = request.form['wiki']
    conn = pymysql.connect(
        host='tools-db',
        read_default_file=os.path.expanduser("~/replica.my.cnf"),
        charset='utf8mb4',
        database=app.config['DB_NAME']
    )
    with conn.cursor() as cur:
        sql = 'insert into queue(users, subject, text, wiki) values (%s, %s, %s, %s)'
        cur.execute(sql, (users, subject, text, wiki))
        cur.commit()
    return 'done'


@app.route('/sendmails', methods=['POST'])
def sendmails():
    users = request.form['users'].replace('\r', '').split('\n')
    subject = request.form['subject']
    text = request.form['text']
    wiki = request.form['wiki']
    if "ccme" in request.form:
        ccme = 1
    else:
        ccme = 0
    API_URL = 'https://%s/w/api.php' % wiki

    for user in users:
        payload = {
            "action": "query",
            "format": "json",
            "meta": "tokens",
            "type": "csrf"
        }
        r = requests.get(API_URL, params=payload, auth=get_auth())
        token = r.json()['query']['tokens']['csrftoken']
        payload = {
            "action": "emailuser",
            "format": "json",
            "target": user,
            "subject": subject,
            "text": text,
            "token": token,
            "ccme": ccme
        }
        r = requests.post(API_URL, data=payload, auth=get_auth())
    flash(_('success-text'), 'success')
    return redirect(flask.url_for('index'))


def get_auth():
    request_token_secret = flask.session.get('request_token_secret', None)
    request_token_key = flask.session.get('request_token_key', None)
    auth = OAuth1(key, secret, request_token_key, request_token_secret)
    return auth


def logged():
    return flask.session.get('username') is not None


def getusername():
    return flask.session.get('username')


@app.context_processor
def inject_base_variables():
    return {
        "logged": logged(),
        "username": getusername()
    }


@app.route('/login')
def login():
    """Initiate an OAuth login.
    Call the MediaWiki server to get request secrets and then redirect the
    user to the MediaWiki server to sign the request.
    """
    consumer_token = mwoauth.ConsumerToken(
        app.config['CONSUMER_KEY'], app.config['CONSUMER_SECRET'])
    try:
        redirect, request_token = mwoauth.initiate(
            app.config['OAUTH_MWURI'], consumer_token)
    except Exception:
        app.logger.exception('mwoauth.initiate failed')
        flash(_('login-fail-text', url="https://phabricator.wikimedia.org/maniphest/task/edit/form/1/?project=massmailer"), 'danger')
        return flask.redirect(flask.url_for('index'))
    else:
        flask.session['request_token'] = dict(zip(
            request_token._fields, request_token))
        flash(_('login-success-text'), 'success')
        return flask.redirect(redirect)


@app.route('/oauth-callback')
def oauth_callback():
    """OAuth handshake callback."""
    if 'request_token' not in flask.session:
        flask.flash(_('oauth-callback-failed-text'))
        return flask.redirect(flask.url_for('index'))
    consumer_token = mwoauth.ConsumerToken(app.config['CONSUMER_KEY'], app.config['CONSUMER_SECRET'])

    try:
        access_token = mwoauth.complete(
            app.config['OAUTH_MWURI'],
            consumer_token,
            mwoauth.RequestToken(**flask.session['request_token']),
            flask.request.query_string)
        identity = mwoauth.identify(app.config['OAUTH_MWURI'], consumer_token, access_token)
    except Exception:
        app.logger.exception('OAuth authentication failed')
    else:
        flask.session['request_token_secret'] = dict(zip(access_token._fields, access_token))['secret']
        flask.session['request_token_key'] = dict(zip(access_token._fields, access_token))['key']
        flask.session['username'] = identity['username']

    return flask.redirect(flask.url_for('index'))


@app.route('/logout')
def logout():
    """Log the user out by clearing their session."""
    flask.session.clear()
    flash(_('logout-text'), 'success')
    return flask.redirect(flask.url_for('index'))


if __name__ == "__main__":
    app.run(debug=True, threaded=True)
