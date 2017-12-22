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
import os
import shutil
import requests
from json import JSONDecodeError

from celery import task, current_app
from celery.utils.log import get_task_logger

from deeptracy_core.dal.project.project_hooks import ProjectHookType
from deeptracy_core.dal.database import db
from deeptracy_core.dal.scan.manager import get_scan, ScanState
from deeptracy_core.dal.scan_dep.manager import get_scan_deps
from deeptracy_core.dal.scan_vul.manager import add_scan_vul

from ..config import SHARED_VOLUME_PATH
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
        scan_deps_len = len(scan_deps)

        scan = get_scan(scan_id, session)
        project = scan.project

        total_vulnerabilities = []

        def get_response(i, scan_dep):
            [package, version] = scan_dep
            url = 'http://localhost:8000/{package}/{version}'.format(package=package, version=version)

            response = requests.get(url).json()
            logger.info("Procesado {} de {}".format(i, scan_deps_len))

            if response:
                total_vulnerabilities.append([package, version])
                # save all dependencies in the database
                add_scan_vul(scan.id, package, version, response, session)
                session.commit()
                logger.debug('saved {vulnerabilities} vulnerabilities for package {package}:{version}'.format(
                    vulnerabilities=len(response), package=package, version=version))
        [get_response(i, scan_dep) for i, scan_dep in enumerate(scan_deps)]

        scan.total_vulnerabilities = len(total_vulnerabilities)
        scan.state = ScanState.DONE
        session.add(scan)
        session.commit()

        # After the merge we remove the folder with the scan source
        scan_dir = os.path.join(SHARED_VOLUME_PATH, scan_id)
        try:
            shutil.rmtree(scan_dir)
        except IOError as e:
            logger.error("Error while removing tmp dir: {} - {}".format(
                scan_dir,
                e
            ))

        if project.hook_type != ProjectHookType.NONE.name:
            # launch notify task
            logger.debug('{} launch notify task for project.hook_type'.format(scan.id))

            notify_results.delay(scan.id)

