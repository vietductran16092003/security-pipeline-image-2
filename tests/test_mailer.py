from email import message_from_bytes
from email.header import decode_header, make_header

from scanner.mailer import send_email


class FakeSMTP:
    def __init__(self):
        self.host = None
        self.login_args = None
        self.sent_to = None
        self.raw = None

    def __call__(self, host, port, **kw):
        self.host = (host, port)
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def login(self, user, password):
        self.login_args = (user, password)

    def sendmail(self, from_addr, to_addrs, msg):
        self.sent_to = to_addrs
        self.raw = msg if isinstance(msg, bytes) else msg.encode()


def test_send_email_uses_ssl_465_and_utf8_subject():
    fake = FakeSMTP()
    send_email("[my-api] 3 lỗi P1", "<b>x</b>", "u@gmail.com", "p", "to@x.com", smtp_factory=fake)
    assert fake.host == ("smtp.gmail.com", 465)
    assert fake.login_args == ("u@gmail.com", "p")
    assert fake.sent_to == ["to@x.com"]
    msg = message_from_bytes(fake.raw)
    assert str(make_header(decode_header(msg["Subject"]))) == "[my-api] 3 lỗi P1"
    assert msg.is_multipart()
    assert [p.get_content_type() for p in msg.get_payload()] == ["text/plain", "text/html"]


def test_multiple_recipients_comma_separated():
    fake = FakeSMTP()
    send_email("s", "<b>x</b>", "u", "p", "a@x.com, b@x.com", smtp_factory=fake)
    assert fake.sent_to == ["a@x.com", "b@x.com"]
