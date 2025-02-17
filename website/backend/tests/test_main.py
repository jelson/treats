from moto import mock_aws
import boto3
import cherrypy
import datetime
import json
import os
import pytest
import re
import requests
import sys
import pyotp

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src import v1


@pytest.fixture
def sonde_mock_aws(request):
    _mock = mock_aws()
    _mock.start()

    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

    request.cls.WindowApiPassword = "the_display_password"
    SECRET_NAME = "aws_secret_name"
    os.environ["SECRET_NAME"] = SECRET_NAME
    sm = boto3.client("secretsmanager")
    sm.create_secret(
        Name=SECRET_NAME,
        SecretString=json.dumps(
            {
                "WindowApiPassword": request.cls.WindowApiPassword,
                "OTPSecret": pyotp.random_base32(),
            }
        ),
    )

    # table_definitions.create_tables()

    yield

    _mock.stop()


# general strategy for doing unit tests with cherrypy cribbed from:
#   https://schneide.blog/2017/02/06/integration-tests-with-cherrypy-and-requests/
@pytest.fixture
def server(request, sonde_mock_aws):
    request.cls.apiserver = v1.mount_server_instance(dev_mode=True)
    request.cls.user_tokens = {}
    cherrypy.config.update(
        {
            "request.throw_errors": True,
        }
    )
    cherrypy.engine.start()
    cherrypy.engine.wait(cherrypy.engine.states.STARTED)
    yield
    cherrypy.engine.exit()
    cherrypy.engine.block()


def get(
    url_suffix,
    expected_status=200,
    headers=None,
    params=None,
    cookies=None,
) -> requests.Response:
    url = f"http://127.0.0.1:8080/{url_suffix}"
    resp = requests.get(
        url,
        headers=headers,
        params=params,
        cookies=cookies,
    )
    assert resp.status_code == expected_status, f"Got error: {resp.text}"
    return resp


def post(
    url_suffix,
    expected_status=200,
    headers=None,
    data=None,
    cookies=None,
) -> requests.Response:
    url = f"http://127.0.0.1:8080/{url_suffix}"
    resp = requests.post(
        url,
        headers=headers,
        data=data,
        cookies=cookies,
    )
    assert resp.status_code == expected_status, f"Got error: {resp.text}"
    return resp


@pytest.mark.usefixtures("server")
class Test_v1:
    def test_hello(self):
        resp = get("hello")
        assert "hello from the v1 feeder api" in resp.text

    def test_get_window_image_without_auth(self):
        get("get_window_image", expected_status=400)

    def test_get_window_image_without_format_arg(self):
        get(
            "get_window_image",
            headers={
                "X-Feeder-Auth": self.WindowApiPassword,
            },
            expected_status=400,
        )

    def test_get_window_image(self):
        resp = get(
            "get_window_image",
            headers={
                "X-Feeder-Auth": self.WindowApiPassword,
            },
            params={
                'format': 'png',
            }
        )
        with open("test-image.png", "wb") as f:
            f.write(resp.content)

    def test_valid_otp(self):
        url = self.apiserver._get_auth_url()
        code = re.search(r'auth/(\d+)', url).group(1)
        get(
            "verify_scan",
            cookies={
                'otp': code,
            }
        )

    def test_slightly_old_otp(self):
        t = datetime.datetime.now() - datetime.timedelta(seconds=self.apiserver.CODE_VALIDITY_SECONDS)
        url = self.apiserver._get_auth_url(at=t)
        code = re.search(r'auth/(\d+)', url).group(1)
        get(
            "verify_scan",
            cookies={
                'otp': code,
            }
        )

    def test_too_old_otp(self):
        t = datetime.datetime.now() - datetime.timedelta(seconds=self.apiserver.CODE_VALIDITY_SECONDS + 60)
        url = self.apiserver._get_auth_url(at=t)
        code = re.search(r'auth/(\d+)', url).group(1)
        resp = get(
            "verify_scan",
            cookies={
                'otp': code,
            },
            expected_status=400,
        )
        assert 'need a recent QR code' in resp.text
