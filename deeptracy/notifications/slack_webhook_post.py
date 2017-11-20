"""
Detailed documentation of Slack Incoming Webhooks:
https://api.slack.com/incoming-webhooks
"""

import json
import requests
import logging

from deeptracy_core.dal.project.model import Project

log = logging.getLogger(__name__)


def notify(webhook_url: str, project: Project, vulnerabilities: str):

    notif_text = 'project at {} has vulnerabilities: \n {}'.format(project.repo, vulnerabilities)
    log.info('notify to SLACK -> {}'.format(notif_text))

    slack_data = {'text': notif_text}

    response = requests.post(
        webhook_url,
        data=json.dumps(slack_data),
        headers={'Content-Type': 'application/json'}
    )

    if response.status_code != 200:
        raise ValueError(
            'Request to slack returned an error %s, the response is:\n%s'
            % (response.status_code, response.text)
        )
