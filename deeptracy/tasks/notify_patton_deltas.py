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
from celery import task

from deeptracy.tasks.base_task import DeeptracyTask
from deeptracy_core.dal.database import db
from deeptracy_core.dal.scan_dep.manager import get_scan_by_raw_dep
from deeptracy.notifications.manager import notify_deltas

logger = logging.getLogger('deeptracy')


@task(name="notify_patton_deltas", base=DeeptracyTask)
def notify_patton_deltas(dependencies):
    scan_dep_by_project_id = {}
    with db.session_scope() as session:
        for raw_dep in dependencies:
            scan_deps = get_scan_by_raw_dep(raw_dep, session)
            for scan_dep in scan_deps:
                project = scan_dep.scan.project
                if project.id in scan_dep_by_project_id:
                    scan_dep_by_project_id[project.id]['dependencies'].append(raw_dep)
                else:
                    scan_dep_by_project_id[project.id] = {'project': project, 'dependencies': [raw_dep]}
        for project_id in scan_dep_by_project_id:
            elem = scan_dep_by_project_id[project_id]
            notify_deltas(elem['project'], elem['dependencies'])
    logger.debug('notify vulnerabilities')


def format_notify_text(dependencies):
    return " , ".join(dependencies)
