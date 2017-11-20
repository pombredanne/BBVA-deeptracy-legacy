# Copyright 2017 BBVA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import json
from celery import task

from deeptracy_core.dal.database import db
from deeptracy_core.dal.scan.manager import get_scan
from deeptracy_core.dal.project.project_hooks import ProjectHookType
from deeptracy_core.dal.scan_vul.manager import get_scan_vulnerabilities

import deeptracy.notifications.slack_webhook_post as slack
import deeptracy.notifications.email_send as email

logger = logging.getLogger('deeptracy')


@task(name="notify_results")
def notify_results(scan_id):
    with db.session_scope() as session:
        scan = get_scan(scan_id, session)
        project = scan.project

        logger.debug('notify project data {}'.format(project.hook_data))

        vul_list = []
        if project.hook_type != ProjectHookType.NONE.name:
            vul_list = get_scan_vulnerabilities(scan_id, session)

        vul_txt = ''
        for vul in vul_list:
            vul_txt += '{library} {version} {severity} {summary} {advisory} \n'.format(
                library=vul.library,
                version=vul.version,
                severity=vul.severity,
                summary=vul.summary,
                advisory=vul.advisory
            )

        if project.hook_type == ProjectHookType.SLACK.name:
            hook_data_dict = json.loads(project.hook_data)
            slack.notify(hook_data_dict.get('webhook_url'), project, vul_txt)
        elif project.hook_type == ProjectHookType.EMAIL.name:
            hook_data_dict = json.loads(project.hook_data)
            email.notify(hook_data_dict.get('email'), project, vul_txt)
