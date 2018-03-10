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
import simplejson as json
import requests
from flask import redirect, request, jsonify, make_response
import mwoauth
import mwparserfromhell
from requests_oauthlib import OAuth1
import random
import toolforge

app = flask.Flask(__name__)
application = app

requests.utils.default_user_agent = lambda: "MassMailer (https://tools.wmflabs.org/massmailer; martin.urbanec@wikimedia.cz)"

# Load configuration from YAML file
__dir__ = os.path.dirname(__file__)
#app.config.update(
    #yaml.safe_load(open(os.path.join(__dir__, 'config.yaml'))))

#key = app.config['CONSUMER_KEY']
#secret = app.config['CONSUMER_SECRET']

@app.route('/')
def index():
	return flask.render_template('index.html', username=flask.session.get('username'))

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
		return flask.redirect(flask.url_for('index'))
	else:
		flask.session['request_token'] = dict(zip(
		request_token._fields, request_token))
		return flask.redirect(redirect)


@app.route('/oauth-callback')
def oauth_callback():
	"""OAuth handshake callback."""
	if 'request_token' not in flask.session:
		flask.flash(u'OAuth callback failed. Are cookies disabled?')
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
	return flask.redirect(flask.url_for('index'))

if __name__ == "__main__":
	app.run(debug=True, threaded=True)
