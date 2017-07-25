import os
import json

from tornado.log import app_log, enable_pretty_logging
from tornado.auth import GoogleOAuth2Mixin
from tornado.gen import coroutine
from tornado.httpclient import AsyncHTTPClient
from tornado.httputil import url_concat
from tornado.ioloop import IOLoop
from tornado import web

class GoogleOAuth2LoginHandler(web.RequestHandler,
                               GoogleOAuth2Mixin):
    @coroutine
    def get(self):
        if not self.get_argument('code', False):
            return self.authorize_redirect(
                redirect_uri=self.settings['redirect_uri'],
                client_id=self.settings['google_oauth']['key'],
                scope=['profile', 'email'],
                response_type='code',
                extra_params={'approval_prompt': 'auto'})

        access_reply = yield self.get_authenticated_user(
            redirect_uri=self.settings['redirect_uri'],
            code=self.get_argument('code'))

        resp = yield AsyncHTTPClient().fetch(
            url_concat(
                self._OAUTH_USERINFO_URL,
                {'access_token': access_reply['access_token']},
            )
        )

        user = json.loads(resp.body.decode())

        app_log.info("User logged in %r", user)
        # could also self the whole user dict somewhere here
        self.set_secure_cookie('google-email', user['email'])
        # send them back to root
        self.redirect('/')

class MainHandler(web.RequestHandler):
    """The main handler.
    
    Triggers OAuth for login, then redirects to the appropriate Hub.
    """

    def get_current_user(self):
        return self.get_secure_cookie('google-email')

    @web.authenticated
    def get(self):
        email = self.get_secure_cookie('google-email')
        self.write(email)
        return
        # TODO:
        # hub_url = self.hub_for_user(email)
        # set a cookie for nginx in front to use for routing:
        # self.set_cookie('which-hub', hub_url)
        # create a temporary token for the Authenticator to use to finish login
        # token = self.new_login_token()
        # self.save_token(token)
        # self.redirect(hub + '/login?dispatch_token=token')

class TokenHandler(web.RequestHandler):
    """Handler for Authenticators to hit, turning a token into an email address"""
    def get_current_user(self):
        # Probably check Authorization header for an API token
        # shared with the Hubs' Authenticators
        return

    @web.authenticated
    def get(self):
        token = self.get_argument('token')
        if not token:
            raise web.HTTPError(400)
        user_email = self.email_for_token(token)
        # Expire tokens. Only allow using them once.
        self.expire_token(token)
        # reply with email:
        self.set_header('content-type', 'application/json')
        self.write(json.dumps({'email': user_email}))

def main():
    """docstring for main"""
    settings = {}
    app = web.Application([
        ('/oauth', GoogleOAuth2LoginHandler),
        ('/', MainHandler),
        ('/api/token', TokenHandler),
    ],
        google_oauth={
            'key': os.environ['OAUTH_CLIENT_ID'],
            'secret': os.environ['OAUTH_CLIENT_SECRET'],
        },
        redirect_uri=os.environ['REDIRECT_URI'],
        login_url='/oauth',
        cookie_secret=os.urandom(32),
    )
    app.listen(8000)
    enable_pretty_logging()
    IOLoop.current().start()

if __name__ == '__main__':
    main()
