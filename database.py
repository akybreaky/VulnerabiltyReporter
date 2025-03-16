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


def init_or_update_db() -> bool:
    try:
        load_cwe_data()
        if update_repo():
            load_repo_data()
    except Exception as e:
        print(f"{e}", file=sys.stderr)
        return False

    return True

def load_cwe_data():
    if not cwe_list_exists():
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

def init_repo() -> bool:
    if repo_exists():
        return True

    try:
        print("Cloning Advisory Database...")
        subprocess.run(['git', 'clone', REPO_URL, REPO_PATH, '--depth=1', '-b', 'main', '--single-branch'],
                       check=True)
    except subprocess.CalledProcessError as e:
        raise Exception("Failed to clone the advisory repository") from e

    return True


def update_repo() -> bool:
    if not repo_exists():
        return init_repo()

    print("Updating Advisory Database...")

    old_path = os.getcwd()
    os.chdir(REPO_PATH)
    try:
        output = subprocess.check_output(['git', 'pull'])
        print(output.decode('utf-8'))
    except subprocess.CalledProcessError as e:
        os.chdir(old_path) # Return to the original directory
        raise Exception("Failed to pull the latest changes in the advisory-database") from e

    os.chdir(old_path) # Return to the original directory

    # If output contains "Already up to date.", we don't need to update the local db
    if b'Already up to date.' in output:
        print("Local database is already up to date.")
        return False
    return True

def load_repo_data() -> bool:
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
            val: Cwe | None = Cwe.query.get(cwe[4:]) # Get the cwe_id without the "CWE-" prefix
            if val is not None:
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

def fetchAllCVEs():
    if not db_exists():
        init_or_update_db()
    print("Fetching all CVEs")
    cve_ids = db.session.query(Advisory.cve_id).all()

    # Extract cve_id values from the query result and store them in an array
    cve_id_array = [cve_id[0] for cve_id in cve_ids if cve_id[0] is not None]

    return cve_id_array
     

def repo_exists() -> bool:
    return os.path.exists(REPO_PATH)

def cwe_list_exists() -> bool:
    return os.path.exists(CWE_PATH)
def db_exists()->bool:
    return os.path.exists(DB_PATH)

