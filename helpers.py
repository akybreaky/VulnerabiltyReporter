import glob
import json
import os
import subprocess
import sys

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text,case,func

import utils
from utils import get_path, str_to_date
import xml.etree.ElementTree as ET

db = SQLAlchemy()

from models import Cwe, Advisory, Package


def fetchAllCVEs():
    if not db_exists():
        init_or_update_db()
    print("Fetching all CVEs")
    cve_ids = db.session.query(Advisory.cve_id).all()

    cve_id_array = [cve_id[0] for cve_id in cve_ids if cve_id[0] is not None]

    return cve_id_array

def fetchAllCWEs():
    if not db_exists():
        init_or_update_db()
    print("Fetching all CWEs")
    cwe_ids = db.session.query(Cwe.cwe_id).all()

    cwe_id_array = [cwe_id[0] for cwe_id in cwe_ids if cwe_id[0] is not None]

    return cwe_id_array

def filterCVEs(filters: dict):
    """Filters CVEs based on a dictionary of filters. (e.g. {'severity': 'high', 'projectName': 'example', 'orderBy': 'published', 'order': 'desc'})"""
    q = db.session.query(Advisory)
    orderBy = Advisory.advisory_id
    ascending = True
    #assign values to severity scores for ordering
    severity_order = case(
        value=Advisory.severity,
        whens={
            'LOW': 1,
            'MODERATE': 2,
            'HIGH': 3,
            'CRITICAL': 4,
        }
    )
    if 'severity' in filters:
        q = q.filter(Advisory.severity == filters['severity'])

    if 'projectName' in filters:
        q = q.join(Package).filter(Package.package_name == filters['projectName'])

    if 'orderBy' in filters:
        if filters['orderBy'] == 'severity':
            orderBy = severity_order
        elif filters['orderBy'] == 'published':
            orderBy = Advisory.published
        elif filters['orderBy'] == 'modified':
            orderBy = Advisory.modified
        elif filters['orderBy'] == 'withdrawn':
            orderBy = Advisory.withdrawn
        elif filters['orderBy'] == 'advisory_id':
            orderBy = Advisory.advisory_id
        elif filters['orderBy'] == 'cve_id':
            year_part = func.substring(Advisory.cve_id, 5, 4)
            number_part = func.substring(Advisory.cve_id, 10)
            if ascending:
                q.order_by(func.cast(year_part, db.Integer).asc())
                q.order_by(func.cast(number_part, db.Integer).asc())
            else:
                q.order_by(func.cast(year_part, db.Integer).desc())
                q.order_by(func.cast(number_part, db.Integer).desc())

    if 'order' in filters:
        if filters['order'] == 'desc':
            ascending = False
        elif filters['order'] == 'asc':
            ascending = True

    if 'withdrawn' in filters:
        print()
        #in chronological order


    if ascending:
        q.order_by(orderBy.asc())
    else:
        q.order_by(orderBy.desc())

    return q.all()
    
def getProjectCVEs():
    results = db.session.query(Package.package_name, Advisory.cve_id) \
                        .join(Advisory, Package.advisory_id == Advisory.advisory_id) \
                        .all()
    #transform results into dicts for python usage
    projectCVEs = []
    for package_name, cve_id in results:
        projectCVEs.append({
            "project": package_name,
            "cve_id": cve_id
        })
    #remove duplicate project entries and glue the CVEs together
    output = []
    for project, cves in projectCVEs.items():
        output.append({"project": project,"cve_ids": cves})
    return output
