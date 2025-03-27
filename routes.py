from sqlalchemy import func

from app import app
from models import *

@app.route('/')
def index():
    cwe = Cwe.query.get(77)

    return f"Testing DB call to CWE-77:<br><br>ID: {cwe.cwe_id}<br>Name: {cwe.name}<br>Description: {cwe.description}"

# This is an example, change this when we have a proper page for it.
@app.route('/top-10-cwes')
def top_10_cwes():
    cwes = Cwe.query.join(advisory_cwe) \
        .with_entities(Cwe.cwe_id, Cwe.name, func.count(Cwe.cwe_id).label('count')) \
        .group_by(Cwe.cwe_id) \
        .order_by(func.count(Cwe.cwe_id).desc()) \
        .limit(10)

    return f"Top 10 CWEs:<br><br>" + "<br>".join([f"Matches ({cwe.count}): CWE-{cwe.cwe_id}: {cwe.name}" for cwe in cwes])

@app.route('/cve-trend')
def cve_trend():
    prefix = "CVE"
    current_year = datetime.utcnow().year
    start_year = current_year - 9  # Last 10 years
    year_counts = {year: 0 for year in range(start_year, current_year + 1)}

    # Query all advisories with non-null CVE IDs and within date range
    advisories = (
        Advisory.query
        .filter(Advisory.cve_id != None)
        .filter(Advisory.published >= datetime(start_year, 1, 1))
        .all()
    )

    # Count CVEs per year using regex on CVE IDs
    for advisory in advisories:
        match = re.match(rf'{prefix}-(\d{{4}})-\d+', advisory.cve_id)
        if match:
            year = int(match.group(1))
            if start_year <= year <= current_year:
                year_counts[year] += 1

    # Create bar chart
    years = list(year_counts.keys())
    counts = list(year_counts.values())

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(years, counts, color='#3478c0')
    ax.set_title("Annual Distribution of Published CVE Records (Last 10 Years)")
    ax.set_xlabel("Year")
    ax.set_ylabel("Number of CVEs")
    plt.xticks(years, rotation=45)
    plt.tight_layout()

    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    chart_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    plt.close()

    return render_template(
        'cve_trend.html',
        prefix=prefix,
        start_year=start_year,
        end_year=current_year,
        chart=chart_base64,
        year_counts=year_counts
    )



