
## Development

### Requirements

- Python 3.11+ [Instructions](https://wiki.python.org/moin/BeginnersGuide/Download)

### Virtual Environment

Make sure all packages you add are added to the `requirements.txt` file.
To add a package to the `requirements.txt` file run `pip freeze > requirements.txt`.

Note you may need to replace `python` with `python3` or `py` depending on your system.

#### Windows

```cmd
python -m pip install --upgrade pip
python -m venv venv
.venv\Scripts\activate
pip install -r requirements.txt
```

#### MacOS/Linux

```bash
python -m pip install --upgrade pip
python -m venv venv
source .venv/bin/activate
pip install -r requirements.txt
```