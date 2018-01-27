import logging
import smtplib
import os
import jinja2
import json

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

log = logging.getLogger(__name__)


def notify(project, subject: str, scan_vulns):
    hook_data_dict = json.loads(project.hook_data)
    email = hook_data_dict.get('email')

    if len(scan_vulns) == 0:
        send_mail(email, subject, create_email_html_template_scan_success(project.name))
    else:
        send_mail(email, subject, create_email_html_template_with_vulnerabilities(project.name, subject, scan_vulns))


def send_mail(email_to: str, subject: str, content: str):

    email_from = "deeptracy.bbvalabs@gmail.com"
    username = "deeptracy.bbvalabs@gmail.com"
    password = "TzharPlquTS6zxe0"
    preamble: str = ""

    log.info('notify to Email -> {}, the text -> {}'.format(email_to, content))

    m = MIMEMultipart('alternative')
    m['Subject'] = subject
    m['From'] = email_from
    m['To'] = email_to
    m.preamble = preamble
    m.attach(MIMEText(content, "html"))

    msg = m.as_string()

    # The actual mail send
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(username, password)
    server.sendmail(email_from, [email_to], msg)
    server.quit()

    log.info('Email sento to  -> {}'.format(email_to))


def render_html(tpl_path, context):
    path, filename = os.path.split(tpl_path)
    return jinja2.Environment(
        loader=jinja2.FileSystemLoader(path or './')
    ).get_template(filename).render(context)


def create_email_html_template_with_vulnerabilities(project_name: str, subject: str, scan_vulns):

    context = {
        'dependencies_number': len(scan_vulns),
        'project_name': project_name,
        'subject': subject,
        'dependencies': [scan_vuln.split(':') for scan_vuln in scan_vulns]
    }
    base_path = os.path.dirname(os.path.abspath(__file__))
    return render_html('{}/templates/email/vulnerabilities.html'.format(base_path), context)


def create_email_html_template_scan_success(project_name: str):

    context = {
        'project_name': project_name
    }
    base_path = os.path.dirname(os.path.abspath(__file__))
    return render_html('{}/templates/email/scan_success.html'.format(base_path), context)
