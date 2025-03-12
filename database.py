import glob
import json
import os
import subprocess
import sys

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

import utils
from utils import get_path, str_to_date
import xml.etree.ElementTree as ET

db = SQLAlchemy()

from models import Cwe, Advisory, Package

REPO_URL = 'https://github.com/github/advisory-database.git'
DATA_PATH = 'data'
REPO_PATH = os.path.join(DATA_PATH, 'advisory-database')
DB_PATH = os.path.join(DATA_PATH, 'advisory.db')
CWE_PATH = os.path.join(DATA_PATH, 'cwe_list.xml')

def init_db():
    return update_repo() and load_cwe_data() and repo_to_db()

def load_cwe_data():
    if not os.path.exists(CWE_PATH):
        print("CWE file not found...", file=sys.stderr)
        return False

    Cwe.query.delete()

    root = ET.parse(CWE_PATH).getroot()
    for row in root[0]:
        cwe = Cwe(
            cwe_id=row.attrib['ID'],
            name=row.attrib['Name'],
            description=row[0].text,
        )
        db.session.merge(cwe)

    db.session.commit()

    return True

def update_repo() -> bool:
    if not os.path.exists(REPO_PATH):
        try:
            print("Cloning Advisory Database...")
            subprocess.run(['git', 'clone', REPO_URL, REPO_PATH, '--depth=1', '-b','main', '--single-branch'], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error: Failed to clone the repository.\n{e}", file=sys.stderr)
            return False

    else:
        old_path = os.getcwd()
        os.chdir(REPO_PATH)
        try:
            print("Updating Advisory Database...")
            subprocess.run(['git', 'pull'], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error: Failed to pull the latest changes.\n{e}", file=sys.stderr)
            os.chdir(old_path) # Return to the original directory
            return False

        os.chdir(old_path) # Return to the original directory

    return True

def repo_to_db() -> bool:
    if not os.path.exists(REPO_PATH):
        if not update_repo():
            return False

    print("Updating local database...")

    json_files = glob.glob(REPO_PATH + '/advisories/github-reviewed/**/*.json', recursive=True)
    data = []
    for json_file in json_files:
        with open(json_file, 'r', encoding='utf-8') as f:
            json_data = json.load(f)
            data.append(json_data)

    db.session.execute(text('DELETE FROM advisory_cwe'))
    Advisory.query.delete()
    Package.query.delete()

    not_found_cwes = set()

    for value in data:
        advisory = Advisory(
            advisory_id=value['id'],
            severity=value['database_specific']['severity'],
            summary=value['summary'],
            details=value['details'],
            cve_id=get_path(value, ['aliases', 0]), # Get the first alias as cve_id
            published=str_to_date(value['published']),
            modified=str_to_date(value['modified']),
            withdrawn=str_to_date(value.get('withdrawn')), # Get withdrawn date if exists
        )

        for cwe in value['database_specific']['cwe_ids']:
            val: str | None= Cwe.query.get(cwe[4:]) # Get the cwe_id without the "CWE-" prefix
            if val:
                advisory.cwes.append(val)
            else:
                not_found_cwes.add(int(cwe[4:]))

        for package in value['affected']:
            package_name = package['package']['name']
            package_ecosystem = package['package']['ecosystem']
            introduced_version = get_path(package, ['ranges', 0, 'events', 0, 'introduced'])
            fixed_version = get_path(package, ['ranges', 0, 'events', 1, 'fixed'])

            advisory.packages.append(Package(
                advisory_id=value['id'],
                package_name=package_name,
                package_ecosystem=package_ecosystem,
                introduced_version=introduced_version,
                fixed_version=fixed_version,
            ))

        # Don't ask me why this is needed but it is trust me.
        # I spent a good 2 hours figuring this out but this is the only thing that worked
        temp = utils.remove_duplicates(advisory.packages)
        advisory.packages = []
        advisory.packages = temp

        if not_found_cwes:
            print(f"Warning: The following CWEs were not found in the database: {sorted(not_found_cwes)}")

        db.session.merge(advisory)

    db.session.commit()
    print("Local database updated successfully.")
    return True

