"""
Detailed documentation of Slack Incoming Webhooks:
https://api.slack.com/incoming-webhooks
"""
import smtplib
import logging

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from deeptracy_core.dal.project.model import Project

from ..config import DEEPTRACY_EMAIL, SMTP_HOST

log = logging.getLogger(__name__)


def notify(email_to: str, project: Project, vulnerabilities: str):

    # Create message container - the correct MIME type is multipart/alternative.
    msg = MIMEMultipart('alternative')
    msg['Subject'] = 'Deeptracy Vulnerabilities Spotted!'
    msg['From'] = DEEPTRACY_EMAIL
    msg['To'] = email_to

    text = 'Hi!\nHere the vulnerabilities list spotted:\n' + vulnerabilities
    html = """\
    <html>
      <head></head>
      <body>
        <p>Hi!<br>
           Here the vulnerabilities list spotted:<br>
           {vulnerabilities}
        </p>
      </body>
    </html>
    """.format(vulnerabilities=vulnerabilities)

    part1 = MIMEText(text, 'plain')
    part2 = MIMEText(html, 'html')

    msg.attach(part1)
    msg.attach(part2)

    # Send the message via local SMTP server.
    s = smtplib.SMTP(SMTP_HOST)
    s.sendmail(DEEPTRACY_EMAIL, email_to, msg.as_string())
    s.quit()
