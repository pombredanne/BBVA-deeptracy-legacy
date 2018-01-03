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

from celery import task
from celery.utils.log import get_task_logger

from deeptracy_core.dal.project.project_hooks import ProjectHookType
from deeptracy_core.dal.database import db
from deeptracy_core.dal.scan.manager import get_scan, update_scan_state, ScanState
from deeptracy_core.dal.scan_dep.manager import get_scan_deps
from deeptracy_core.dal.scan_vul.manager import add_scan_vul

from ..config import SHARED_VOLUME_PATH, PATTON_URI
from .notify_results import notify_results

logger = get_task_logger('deeptracy')


@task(name="get_vulnerabilities")
def get_vulnerabilities(scan_id: str):
    with db.session_scope() as session:
        logger.debug('{} extract dependencies'.format(scan_id))

        scan_deps = []

        logger.info(PATTON_URI)
        logger.info(PATTON_URI)
        logger.info(PATTON_URI)
        logger.info(PATTON_URI)
        logger.info(PATTON_URI)
        logger.info(PATTON_URI)
        logger.info(PATTON_URI)
        logger.info(PATTON_URI)
        logger.info(PATTON_URI)
        logger.info(PATTON_URI)
        logger.info(PATTON_URI)
        logger.info(PATTON_URI)
        logger.info(PATTON_URI)
        logger.info(PATTON_URI)
        logger.info(PATTON_URI)
        logger.info(PATTON_URI)
        logger.info(PATTON_URI)


        def format(raw_dep):

            parts = raw_dep.split(':')
            if len(parts) == 3:
                library_parts = parts[1].split('@')

                if len(library_parts) > 2:
                    name_package = '@'.join(library_parts[:-1])
                else:
                    name_package = library_parts[0]

                version_part = library_parts[-1]
                scan_deps.append([name_package, version_part])

        scans_deps_aux = get_scan_deps(scan_id, session)
        [format(scan.raw_dep) for scan in scans_deps_aux]
        scan_deps_len = len(scan_deps)

        scan = get_scan(scan_id, session)
        project = scan.project

        total_vulnerabilities = []

        def get_response(i, scan_dep):
            [package, version] = scan_dep
            url = '{}/batch'.format(PATTON_URI)

            response = requests.post(url, json=[scan_dep]).json()
            logger.info("Procesado {} de {}".format(i, scan_deps_len))

            if response:
                for key in response:
                    if response[key]:
                        total_vulnerabilities.append([package, version])
                        # save all dependencies in the database
                        add_scan_vul(scan.id, package, version, response[key], session)
                        session.commit()
                        logger.debug('saved {vulnerabilities} vulnerabilities for package {package}:{version}'.format(
                            vulnerabilities=len(response), package=package, version=version))

        [get_response(i, scan_dep) for i, scan_dep in enumerate(scan_deps)]

        scan.total_vulnerabilities = len(total_vulnerabilities)
        update_scan_state(scan, ScanState.DONE, session)
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
