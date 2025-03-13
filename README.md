
## Development

### Requirements

- Python 3.12+ [Instructions](https://wiki.python.org/moin/BeginnersGuide/Download)

### Setup

Make sure all packages you add are added to the `requirements.txt` file.
To add a package to the `requirements.txt` file run `pip freeze > requirements.txt` inside the virtual environment.

Note you may need to replace `python` with `python3` or `py` depending on your system.

#### 1. Upgrade pip

```bash
python -m pip install --upgrade pip
```


#### 2. Create a virtual environment  

##### Windows

```bash
python -m venv venv
venv\Scripts\activate
```  

##### MacOS/Linux

```bash
python -m venv venv
source venv/bin/activate
```


#### 3. Install the requirements

```bash
pip install -r requirements.txt
```

#### 4. Run the application

```bash
python app.py
## or
python app.py --no-update # to skip the update check (development only)
```



## References

- [GitHub Advisory Database](https://github.com/github/advisory-database)
- [CWE List](https://cwe.mitre.org/data/index.html)