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
import requests

from celery import task
from celery.utils.log import get_task_logger
from deeptracy_core.dal.project.project_hooks import ProjectHookType
from deeptracy_core.dal.database import db
from deeptracy_core.dal.scan.manager import get_scan
from deeptracy_core.dal.scan_dep.manager import get_scan_deps

from .notify_results import notify_results


logger = get_task_logger('deeptracy')


@task(name="get_vulnerabilities")
def get_vulnerabilities(scan_id: str):
    with db.session_scope() as session:
        logger.debug('{} extract dependencies'.format(scan_id))

        scan_deps = []

        def format(raw_dep):
            [package_part, full_version_part] = raw_dep.split('@')
            name_package = package_part.split(':')[1]
            version_part = full_version_part.split(':')[0]
            scan_deps.append([name_package, version_part])

        [format(scan.raw_dep) for scan in get_scan_deps(scan_id, session)]

        r = requests.post('http://localhost:8080/batch', data=scan_deps)
        response = r.json()
        print(response)

        scan = get_scan(scan_id, session)
        project = scan.project

        if project.hook_type != ProjectHookType.NONE.name:
            # launch notify task
            logger.debug('{} launch notify task for project.hook_type'.format(scan.id))
            notify_results.delay(scan.id)
