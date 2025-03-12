import csv
import glob
import sys
import os
import subprocess
import time
import schedule
import json
import sqlite3

REPO_URL = 'https://github.com/github/advisory-database.git'
DATA_PATH = 'data/'
LOCAL_PATH = os.path.join(DATA_PATH, 'advisory-database')
DB_PATH = os.path.join(DATA_PATH, 'advisory.db')
CWE_PATH = os.path.join(DATA_PATH, 'cwe_list.csv')
CVE_PATH = os.join.path(DATA_PATH,'allCVEs.db')


def get_path(data, path, default=None):
    try:
        for item in path:
            data = data[item]
        return data
    except (KeyError, TypeError, IndexError):
        return default

def init_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS advisories (
            advisory_id TEXT PRIMARY KEY,
            severity TEXT NOT NULL,
            summary TEXT NOT NULL,
            details TEXT NOT NULL,
            cve_id TEXT DEFAULT NULL,
            published DATETIME NOT NULL,
            modified DATETIME NOT NULL,
            withdrawn DATETIME DEFAULT NULL
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS advisory_cwe (
            advisory_id TEXT,
            cwe_id TEXT,
            PRIMARY KEY (advisory_id, cwe_id),
            FOREIGN KEY (advisory_id) REFERENCES advisories(advisory_id),
            FOREIGN KEY (cwe_id) REFERENCES cwe(cwe_id)
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS advisory_package (
            advisory_id TEXT,
            package_name TEXT,
            package_ecosystem TEXT,
            introduced_version TEXT,
            fixed_version TEXT,
            PRIMARY KEY (advisory_id, package_name, package_ecosystem),
            FOREIGN KEY (advisory_id) REFERENCES advisories(advisory_id)
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS cwe (
            cwe_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL
        )
    ''')

    # Load CWE data
    with open(CWE_PATH, 'r', encoding='utf-8') as f:
        cwe_data = csv.DictReader(f)
        db_data = [(i['CWE-ID'], i['Name'], i['Description']) for i in cwe_data]

    cur.executemany('INSERT OR IGNORE INTO cwe VALUES (?, ?, ?)', db_data)

    con.commit()
    con.close()

def update_local_db():
    if not os.path.isfile(DB_PATH):
        print("Database file not found. Initializing database...")
        init_db()

    print("Updating local database...")
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    json_files = glob.glob(LOCAL_PATH + '/advisories/github-reviewed/**/*.json', recursive=True)
    data = []
    for json_file in json_files:
        with open(json_file, 'r', encoding='utf-8') as f:
            json_data = json.load(f)
            data.append(json_data)

    for advisory in data:
        advisory_id = advisory['id']
        severity = advisory['database_specific']['severity']
        summary = advisory['summary']
        details = advisory['details']
        cve_id = get_path(advisory, ['aliases', 0]) # Get the first alias as cve_id
        published = advisory['published']
        modified = advisory['modified']
        withdrawn = advisory.get('withdrawn') # Get withdrawn date if exists

        cur.execute('''
            REPLACE INTO advisories (advisory_id, severity, summary, details, cve_id, published, modified, withdrawn)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (advisory_id, severity, summary, details, cve_id, published, modified, withdrawn))

        # Insert advisory_package
        for package in advisory['affected']:
            package_name = package['package']['name']
            package_ecosystem = package['package']['ecosystem']
            introduced_version = get_path(package, ['ranges', 0, 'events', 0, 'introduced'])
            fixed_version = get_path(package, ['ranges', 0, 'events', 1, 'fixed'])

            cur.execute('''
                INSERT OR IGNORE INTO advisory_package (advisory_id, package_name, package_ecosystem, introduced_version, fixed_version)
                VALUES (?, ?, ?, ?, ?)
            ''', (advisory_id, package_name, package_ecosystem, introduced_version, fixed_version))


        # Insert advisory_cwe
        for cwe in advisory['database_specific']['cwe_ids']:
            cur.execute('''
                INSERT OR IGNORE INTO advisory_cwe (advisory_id, cwe_id)
                VALUES (?, ?)
            ''', (advisory_id, cwe))

    print("Local database updated successfully.")
    con.commit()
    con.close()


def update_repo():
    if not os.path.exists(LOCAL_PATH):
        try:
            print("Cloning Advisory Database...")
            subprocess.run(['git', 'clone', REPO_URL, LOCAL_PATH, '--depth=1', '-b','main', '--single-branch'], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error: Failed to clone the repository.\n{e}", file=sys.stderr)
            return

    else:
        old_path = os.getcwd()
        os.chdir(LOCAL_PATH)
        try:
            print("Updating Advisory Database...")
            subprocess.run(['git', 'pull'], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error: Failed to pull the latest changes.\n{e}", file=sys.stderr)
            return
        finally:
            os.chdir(old_path) # Return to the original directory

    update_local_db()

def fetchAllCVEs():#simplified db to get only basic information
    if not os.path.isfile(DB_PATH):
        update_repo()
    # Connect to the old database (advisory.db)
    old_con = sqlite3.connect(DB_PATH)
    old_cur = old_con.cursor()

    # Retrieve selected fields from the advisories table
    old_cur.execute("""
        SELECT advisory_id, severity, cve_id, published, modified, withdrawn
        FROM advisories
    """)
    filtered_advisories = old_cur.fetchall()

    # Retrieve all data from the advisory_package table
    old_cur.execute("SELECT * FROM advisory_package")
    advisory_package = old_cur.fetchall()

    # Connect to the new database (filtered_advisory.db)
    new_con = sqlite3.connect(CVE_PATH)
    new_cur = new_con.cursor()

    # Create tables in the new database
    new_cur.execute('''
        CREATE TABLE IF NOT EXISTS advisories (
            advisory_id TEXT PRIMARY KEY,
            severity TEXT NOT NULL,
            cve_id TEXT DEFAULT NULL,
            published DATETIME NOT NULL,
            modified DATETIME NOT NULL,
            withdrawn DATETIME DEFAULT NULL
        )
    ''')

    new_cur.execute('''
        CREATE TABLE IF NOT EXISTS advisory_package (
            advisory_id TEXT,
            package_name TEXT,
            package_ecosystem TEXT,
            introduced_version TEXT,
            fixed_version TEXT,
            PRIMARY KEY (advisory_id, package_name, package_ecosystem),
            FOREIGN KEY (advisory_id) REFERENCES advisories(advisory_id)
        )
    ''')

    # Insert data into the new database
    new_cur.executemany('INSERT INTO advisories VALUES (?, ?, ?, ?, ?, ?)', filtered_advisories)
    new_cur.executemany('INSERT INTO advisory_package VALUES (?, ?, ?, ?, ?)', advisory_package)

    # Commit and close connections
    new_con.commit()
    new_con.close()
    old_con.close()


def main():
    if not os.path.exists(DATA_PATH):
        print("data directory does not exist, something went wrong.")
        exit(1)
    if not os.path.isfile(CWE_PATH):
        print("cwe_list.csv file is missing in the data directory, something went wrong.")
        exit(1)

    schedule.every().day.do(update_repo)

    update_repo() # Run it once first
    print("Updated the db")
    fetchAllCVEs()
    print("Created new db")

    while True:
        schedule.run_pending()
        time.sleep(60)



if __name__ == '__main__':
    main()
