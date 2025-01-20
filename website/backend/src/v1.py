#!/usr/bin/env python3

from decimal import Decimal
import boto3
import cherrypy
import datetime
import os
import sys
import time
import json
import pyotp
import qrcode
from io import BytesIO

sys.path.insert(0, os.path.dirname(__file__))
import util

DEFAULT_HOST = "https://sondesearch.lectrobox.com"
DEV_HOST = "http://localhost:4000"
AUTH_LANDING_PAGE = "/auth/"



# A placeholder for expensive setup that should only be done once. This
# iteration of the program no longer has any such setup so this now has nothing
# in it.
class GlobalConfig:
    def __init__(self, dev_mode: bool):
        print("Global setup")
        self.dev_mode = dev_mode
        secretsmanager = boto3.client("secretsmanager")
        self.secrets = json.loads(
            secretsmanager.get_secret_value(SecretId=os.environ["SECRET_NAME"])[
                "SecretString"
            ]
        )


class ClientError(cherrypy.HTTPError):
    def __init__(self, message: str):
        super().__init__()
        print(f"client error: {message}")
        self._msg = message.encode("utf8")

    def set_response(self):
        super().set_response()
        response = cherrypy.serving.response
        response.body = self._msg
        response.status = 400
        response.headers.pop("Content-Length", None)


class FeederAPI:
    def __init__(self, global_config: GlobalConfig):
        self._g = global_config
        # self.tables = table_definitions.TableClients()

    def origin(self):
        return DEV_HOST if self._g.dev_mode else DEFAULT_HOST

    @staticmethod
    def allow_lectrobox_cors(func):
        def wrapper(*args, **kwargs):
            self = args[0]
            origin = self.origin()
            cherrypy.response.headers["Access-Control-Allow-Origin"] = origin
            cherrypy.response.headers["Access-Control-Allow-Credentials"] = "true"
            return func(*args, **kwargs)

        return wrapper

    @staticmethod
    def window_auth_required(func):
        def wrapper(*args, **kwargs):
            auth = cherrypy.request.headers.get("X-Feeder-Auth")
            self = args[0]
            if auth != self._g.secrets["WindowApiPassword"]:
                raise ClientError("no user token in request cookies")
            return func(*args, **kwargs)

        return wrapper

    def _required(self, args, arg):
        if arg not in args:
            raise ClientError(f"missing argument: {arg}")
        if not args[arg]:
            raise ClientError(f"empty argument: {arg}")

        return args[arg]

    def _get_otp(self):
        totp = pyotp.TOTP(self._g.secrets["OTPSecret"])
        totp.digits = 10
        return totp

    @cherrypy.expose
    def hello(self):
        return f"{datetime.datetime.now()}: hello from the v1 feeder api! pid {os.getpid()}"

    def get_time(self):
        return Decimal(time.time())

    @cherrypy.expose
    @allow_lectrobox_cors
    @window_auth_required
    def get_window_image(self, **kwargs):
        self._required(kwargs, "format")
        totp = self._get_otp()
        now = datetime.datetime.now()
        otp = totp.at(now)

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=3,
            border=3,
        )
        qr.add_data(f"{self.origin()}{AUTH_LANDING_PAGE}{otp}")
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        if kwargs["format"] == "png":
            temp = BytesIO()
            img.save(temp, format="png")
            return temp.getvalue()

        raise ClientError("unknown image format")


global_config = None


# This is called both by the uwsgi path, via application(), and the unit test
def mount_server_instance(dev_mode: bool):
    global global_config
    if not global_config:
        global_config = GlobalConfig(dev_mode=dev_mode)

    apiserver = FeederAPI(global_config)
    cherrypy.tree.mount(apiserver)
    return apiserver


# "application" is the magic function called by Apache's wsgi module or uwsgi
def application(environ, start_response):
    mount_server_instance(dev_mode=False)
    cherrypy.config.update(
        {
            "log.screen": True,
            "environment": "production",
            "tools.proxy.on": True,
        }
    )
    return cherrypy.tree(environ, start_response)


# For local testing
if __name__ == "__main__":
    cherrypy.config.update(
        {
            "log.screen": True,
            "server.socket_port": 4001,
        }
    )
    cherrypy.server.socket_host = "::"
    cherrypy.quickstart(
        mount_server_instance(
            retriever=util.LiveSondeHub(),
            dev_mode=True,
        ),
        "/",
    )
