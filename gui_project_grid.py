from sqlalchemy import create_engine, MetaData, Table
from sqlalchemy.orm import sessionmaker
from dash import Dash, html
import dash_ag_grid as dag

db = 'instance/advisory.db' # db address

# fetch data from the advisory database
def get_data_cve():
    engine = create_engine("sqlite:///"+db)
    Session = sessionmaker(bind=engine)
    session = Session()
    
    try:
        # set table
        metadata = MetaData()
        cve_table = Table('advisory', metadata, autoload_with=engine)
        
        # get data from table
        result = session.query(cve_table).all()
        
        # convert rows to a list of dictionaries
        columns = cve_table.columns.keys()                  # get column names
        data = [dict(zip(columns, row)) for row in result]  # map rows to columns
        
        return data
    finally:
        session.close() # ensure session is closed

# fetch data from the cwe database
def get_data_cwe():
    engine = create_engine("sqlite:///"+db)
    Session = sessionmaker(bind=engine)
    session = Session()
    
    try:
        # set table
        metadata = MetaData()
        cwe_table = Table('cwe', metadata, autoload_with=engine)

        # get data from table
        result = session.query(cwe_table).all()
        
        # convert rows to a list of dictionaries
        columns = cwe_table.columns.keys()                  # get column names
        data = [dict(zip(columns, row)) for row in result]  # map rows to columns
        
        return data
    finally:
        session.close() # ensure session is closed

# gets data from advisory.db
cve_data = get_data_cve()
cwe_data = get_data_cwe()

# sets layout depending on selected model: cve, cwe
def set_layout(model):

    if model=="cve":
        # generates column definitions based on the keys of the first row
        column_defs = [{"headerName": key, "field": key} for key in cve_data[0].keys()]
        row_data = cve_data
    elif model=="cwe":
        # generates column definitions based on the keys of the first row
        column_defs = [{"headerName": key, "field": key} for key in cwe_data[0].keys()]
        row_data = cwe_data
    else:
        column_defs = []
    
    # returns grid details to app.layout
    return dag.AgGrid(
        id='vulnerability_reporter',
        columnDefs=column_defs,  # column def
        rowData=row_data,        # row data
        columnSize="autoSize",
        defaultColDef={"resizable": True, "sortable": True, "filter": True},
        dashGridOptions={"pagination": True, "paginationPageSize": 50},
        style={'height': '500px', 'width': '100%'}
    )

# for styling, check out:
# https://www.ag-grid.com/angular-data-grid/theming-colors/#color-schemes
# depends on GUI template