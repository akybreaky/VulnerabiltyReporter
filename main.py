import time

import schedule

import sys
import os
import subprocess

REPO_URL = 'https://github.com/github/advisory-database.git'
LOCAL_PATH = 'advisory-database'

def update_advisory_database():
    if not os.path.exists(LOCAL_PATH):
        try:
            print("Cloning Advisory Database...")
            subprocess.run(['git', 'clone', REPO_URL, LOCAL_PATH, '--depth 1', '-b main', '--single-branch'], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error: Failed to clone the repository.\n{e}", file=sys.stderr)
            return

    os.chdir(LOCAL_PATH)
    try:
        print("Updating Advisory Database...")
        subprocess.run(['git', 'pull'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error: Failed to pull the latest changes.\n{e}", file=sys.stderr)
        return

def main():
    schedule.every().day.do(update_advisory_database)

    update_advisory_database() # Run it once first

    while True:
        schedule.run_pending()
        time.sleep(60)



if __name__ == '__main__':
    main()
