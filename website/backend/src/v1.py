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
from PIL import Image, ImageFont, ImageDraw
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
        self.window_image_size = {'x': 296, 'y': 128}
        self.FONT = ImageFont.truetype(
            os.path.join(os.path.dirname(__file__), "../data/VCR_OSD_MONO_1.21px.ttf"),
            21
        )
        self.CODE_VALIDITY_SECONDS = 60*10

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

    @staticmethod
    def website_auth_required(func):
        def wrapper(*args, **kwargs):
            if 'otp' not in cherrypy.request.cookie:
                raise ClientError("need a QR code scan, friendo")

            self = args[0]
            totp = self._get_otp()
            code = cherrypy.request.cookie['otp'].value
            print(f"Verifying code: {code}")
            if not totp.verify(code, valid_window=self.CODE_VALIDITY_SECONDS // totp.interval):
                raise ClientError("need a recent QR code scan, friendo")

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

    def _get_auth_url(self, at=None):
        totp = self._get_otp()
        if at is None:
            at = datetime.datetime.now()
        otp = totp.at(at)
        return f"{self.origin()}{AUTH_LANDING_PAGE}{otp}"

    @cherrypy.expose
    @window_auth_required
    def get_window_image(self, **kwargs):
        self._required(kwargs, "format")

        # Create QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=3,
            border=3,
        )
        qr.add_data(self._get_auth_url())
        qr.make(fit=True)

        qr_img = qr.make_image(fill_color='black', back_color='white').copy()

        # Create the display image and copy the QR image into it
        img = Image.new(mode='1', color='white', size=(
            self.window_image_size['x'],
            self.window_image_size['y'],
        ))
        qr_x = 5
        qr_y = int((self.window_image_size['y'] - qr_img.size[1]) / 2)
        print(f"image is: {qr_img}, size {qr_img.size}")
        img.paste(qr_img, (qr_x, qr_y))

        # Annotate with text
        text_x = qr_img.size[0] + 30
        draw = ImageDraw.Draw(img)
        now = datetime.datetime.now()
        lines = [
            'Scan to feed',
            'me a treat!',
            '',
            now.strftime("%Y-%m-%d"),
            now.strftime("%H:%M:%S")
        ]
        for i, line in enumerate(lines):
            draw.text((text_x, 10 + (20 * i)), line, 'black', font=self.FONT)

        if kwargs["format"] == "png":
            temp = BytesIO()
            img.save(temp, format="png")
            return temp.getvalue()

        raise ClientError("unknown image format")

    @cherrypy.expose
    @website_auth_required
    def verify_scan(self, **kwargs):
        return 'authorized!'


global_config = None


# This is called both by the uwsgi path, via application(), and the unit test
def mount_server_instance(dev_mode: bool) -> FeederAPI:
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
