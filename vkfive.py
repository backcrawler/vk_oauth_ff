import requests
from flask import Flask, request, redirect, render_template, url_for, make_response
from flask_sqlalchemy import SQLAlchemy
from rauth.service import OAuth2Service

import json
import uuid
import datetime

with open("keys.json", "r") as external_json:
    loaded_dict = json.load(external_json)

# Flask config
SQLALCHEMY_DATABASE_URI = loaded_dict["SQLALCHEMY_DATABASE_URI"]
SQLALCHEMY_TRACK_MODIFICATIONS = True
SECRET_KEY = loaded_dict["SECRET_KEY"]
VK_CLIENT_ID = loaded_dict["VK_CLIENT_ID"]
VK_CLIENT_SECRET = loaded_dict["VK_CLIENT_SECRET"]
API_V = loaded_dict["API_V"]
DEBUG = True

# Flask app
app = Flask(__name__)
app.config.from_object(__name__)
db = SQLAlchemy(app)

# rauth service
oauth_url = 'https://oauth.vk.com/'
vk = OAuth2Service(name='vk',
                   authorize_url='https://oauth.vk.com/authorize',
                   access_token_url='https://oauth.vk.com/access_token',
                   client_id=app.config['VK_CLIENT_ID'],
                   client_secret=app.config['VK_CLIENT_SECRET'],
                   base_url=oauth_url)


class User(db.Model):
    '''Simple user model'''
    id = db.Column(db.Integer, primary_key=True)
    u_id = db.Column(db.String(40), unique=True)
    user_id = db.Column(db.String(80), unique=True)
    token = db.Column(db.String(120))

    def __init__(self, cookie_id, user_id, token):
        self.u_id = cookie_id
        self.user_id = user_id
        self.token = token

    def __repr__(self):
        return f'<User {self.u_id} | {self.user_id}>'


def get_friends(access_token):
    '''Fetches the required number of friends in random order'''
    r = requests.get(
        f'https://api.vk.com/method/friends.get?v={API_V}&count=5&order=random&fields=photo_100&access_token={access_token}')
    friends = json.loads(r.content)
    if friends.get('error'):
        return None
    friends = friends['response']
    friends = friends['items']
    return friends


def get_user():
    '''Gets a user for current session or returns None instead'''
    u_id = request.cookies.get('uuid')
    if u_id is None:
        return None
    user = User.query.filter_by(u_id=u_id).first()
    if not user:
        return None
    return user


@app.route('/')
def index():
    '''Main page, could be accessed beforehand if valid token exists'''
    user = get_user()
    if user is None:
        return render_template('index.html')
    token = user.token
    friends = get_friends(token)
    if friends is None:
        context = {'msg': 'Refresh your login session...'}
        return render_template('index.html', **context)
    context = {'friends': friends}
    return render_template('index.html', **context)


@app.route('/vk/login')
def login():
    '''Login view, redirects to authorization view'''
    redirect_uri = url_for('authorized', _external=True)
    params = {'display': 'popup',
              'redirect_uri': redirect_uri,
              'scope': 'friends,status',
              'response_type': 'code',
              'v': API_V}
    return redirect(vk.get_authorize_url(**params))


@app.route('/vk/authorized')
def authorized():
    '''Authorization and setting required parametrs for the user session'''
    if 'code' not in request.args:
        context = {'msg': 'Invalid request. Authorize once more...'}
        return render_template('index.html', **context)
    u_id = request.cookies.get('uuid')
    code = request.args['code']
    redirect_uri = url_for('authorized', _external=True)
    data = dict(code=code, redirect_uri=redirect_uri)
    # fetching friends json with session
    session = vk.get_auth_session(data=data, decoder=json.loads)
    response = session.access_token_response.json()
    access_token = str(response['access_token'])
    expires_in = response['expires_in']
    user_id = str(response['user_id'])
    friends = get_friends(access_token)
    if friends is None:
        context = {'msg': 'Invalid request. Please log in again...'}
        return render_template('index.html', **context)
    context = {'friends': friends}  # not needed anymore but can come in handy when using straight make_response call
    # creating cookies
    now = datetime.datetime.now()
    expire_date = now + datetime.timedelta(seconds=int(expires_in))
    cookie_id = str(uuid.uuid4())
    # getting user instance
    user = User.query.filter_by(user_id=user_id).first()
    if not user:
        user = User(cookie_id, user_id, access_token)
        db.session.add(user)
    else:
        user.u_id = cookie_id
        user.token = access_token
        db.session.add(user)
    db.session.commit()
    # setting required cookie
    idx = url_for('index')
    resp = redirect(idx)
    resp.set_cookie('uuid', cookie_id, expires=expire_date)
    return resp


@app.route('/vk/logout')
def logout():
    '''
    Deleting user instance in models and removing the cookie
    Deletion is optional and could be changed by developer
    '''
    user = get_user()
    if user is None:
        context = {'msg': 'You are already logged out'}
        return render_template('index.html', **context)
    db.session.delete(user)
    db.session.commit()
    resp = make_response(render_template('index.html'))
    resp.set_cookie('uuid', str(uuid.uuid4()), expires=1)
    return resp


if __name__ == '__main__':
    db.create_all()
    app.run()