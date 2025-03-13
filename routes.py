from app import app
from models import *

@app.route('/')
def index():
    cwe = Cwe.query.get(77)

    return f"Testing DB call to CWE-77:<br><br>ID: {cwe.cwe_id}<br>Name: {cwe.name}<br>Description: {cwe.description}"
