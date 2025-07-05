import json
import logging
from datetime import datetime
from os import environ as env
from urllib.parse import quote_plus, urlencode
from functools import wraps

from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, session, url_for

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.config['PREFERRED_URL_SCHEME'] = 'https'
app.logger.setLevel(logging.INFO)
app.secret_key = env.get("APP_SECRET_KEY")

oauth = OAuth(app)

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)

# Helper decorator for protected routes
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            app.logger.warning(f"Unauthorized access attempt to {url_for(f.__name__)} at {datetime.utcnow().isoformat()}")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

@app.route("/callback")
def callback():
    token = oauth.auth0.authorize_access_token()
    userinfo = token["userinfo"]
    session["user"] = userinfo
    app.logger.info(f"User login: id={userinfo.get('sub')}, email={userinfo.get('email')}, time={datetime.utcnow().isoformat()}")
    return redirect("/dashboard")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html", user=session.get("user"))

@app.route("/protected")
@requires_auth
def protected():
    app.logger.info(f"Access to /protected by {session['user'].get('email')} at {datetime.utcnow().isoformat()}")
    return render_template("protected.html", user=session["user"])

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        f'https://{env.get("AUTH0_DOMAIN")}/v2/logout?'
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000)
