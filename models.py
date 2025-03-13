from database import db
FLASK_ADVISORY_BIND = 'advisorydb'
FLASK_CVE_BIND = 'cvedb'

advisory_cwe = db.Table(
    'advisory_cwe',
    db.Column('advisory_id', db.String, db.ForeignKey('advisory.advisory_id'), primary_key=True),
    db.Column('cwe_id', db.Integer, db.ForeignKey('cwe.cwe_id'), primary_key=True),
    schema = FLASK_ADVISORY_BIND,
)


class Advisory(db.Model):
    __bind_key__=FLASK_ADVISORY_BIND
    advisory_id = db.Column(db.String, primary_key=True)
    severity = db.Column(db.String, nullable=False)
    summary = db.Column(db.String, nullable=False)
    details = db.Column(db.Text, nullable=False)
    cve_id = db.Column(db.String, default=None)
    published = db.Column(db.DateTime, nullable=False)
    modified = db.Column(db.DateTime, nullable=False)
    withdrawn = db.Column(db.DateTime, default=None)
    cwes = db.relationship('Cwe', secondary=advisory_cwe, back_populates='advisories')
    packages = db.relationship('Package', backref='advisory', lazy=True)

class Cwe(db.Model):
    __bind_key__=FLASK_ADVISORY_BIND
    cwe_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    description = db.Column(db.Text, nullable=False)
    advisories = db.relationship('Advisory', secondary=advisory_cwe, back_populates='cwes')

class Package(db.Model):
    __bind_key__=FLASK_ADVISORY_BIND
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    advisory_id = db.Column(db.String, db.ForeignKey('advisory.advisory_id'), nullable=False)
    cve_advisory_id = db.Column(db.String, db.ForeignKey('cve.advisory_id'), nullable=True)  # Links to CVE
    package_name = db.Column(db.String, nullable=False)
    package_ecosystem = db.Column(db.String, nullable=False)
    introduced_version = db.Column(db.String)
    fixed_version = db.Column(db.String)

    # This is needed for the utils.remove_duplicates function
    def __eq__(self, other):
        return (self.advisory_id == other.advisory_id and
                self.package_name == other.package_name and
                self.package_ecosystem == other.package_ecosystem and
                self.introduced_version == other.introduced_version and
                self.fixed_version == other.fixed_version)

class Cve(db.Model):
    __bind_key__=FLASK_CVE_BIND
    advisory_id = db.Column(db.String, primary_key=True)
    severity = db.Column(db.String, nullable=False)
    cve_id = db.Column(db.String, default=None)
    published = db.Column(db.DateTime, nullable=False)
    modified = db.Column(db.DateTime, nullable=False)
    withdrawn = db.Column(db.DateTime, default=None)

    # Explicit foreign key relation to Package
    packages = db.relationship('Package',foreign_keys='Package.cve_advisory_id',backref='cve',lazy=True)