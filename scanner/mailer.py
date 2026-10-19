"""Gửi email báo cáo qua Gmail SMTP (App Password)."""

from __future__ import annotations

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.header import Header

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
PLAIN_TEXT = "Báo cáo bảo mật dạng HTML. Hãy mở email bằng ứng dụng hỗ trợ HTML (ví dụ Gmail)."


def send_email(subject: str, html: str, user: str, password: str, to: str,
               smtp_factory=smtplib.SMTP_SSL) -> None:
    recipients = [x.strip() for x in to.split(",") if x.strip()]
    msg = MIMEMultipart("alternative")
    msg["Subject"] = Header(subject, "utf-8")
    msg["From"] = user
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(PLAIN_TEXT, "plain", "utf-8"))
    msg.attach(MIMEText(html, "html", "utf-8"))
    with smtp_factory(SMTP_HOST, SMTP_PORT, timeout=60) as smtp:
        smtp.login(user, password)
        smtp.sendmail(user, recipients, msg.as_bytes())
