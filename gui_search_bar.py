import sqlite3
from sqlalchemy import create_engine, MetaData, Table
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text 
from dash import Dash, html, callback
from dash import dcc
from dash.dependencies import Input,Output, State
from dash.exceptions import PreventUpdate

db = 'instance/advisory.db' # db address
data = []

#Query to get all matching IDs
def get_data(search_value):
    tempstr = str(search_value)+'%'
    engine = create_engine("sqlite:///"+db)
    
    Session = sessionmaker(bind=engine)
    session = Session()
    sql_statment = text("SELECT * FROM advisory where advisory_id LIKE :val Limit 10")
    cursor = session.execute(sql_statment, {"val" : tempstr})
    tuples = list(cursor.fetchall())
    session.close()
    return tuples
    
#Extracting the IDs from query
def get_ID_data(tuples):
    id_data = []
    for i in range(len(tuples)):
        id_data.append(str(tuples[i][0]))
    return id_data

app = Dash(__name__)

#Setting the Layout
app.layout = html.Div([
    html.H1("Enter a CVE ID to browse to a specific project:"),
    dcc.Dropdown(id = 'my-input', maxHeight=300),
    html.Br(),
    html.Div(html.Table([
        html.Tr([html.Th('Advisory ID'), html.Td(id='my-output')]),
        html.Tr([html.Th('CVE ID'), html.Td(id='my-output-4')]),
        html.Tr([html.Th('CWE ID(s)'), html.Td(id='my-output-8')]),
        html.Tr([html.Th('Severity'), html.Td(id='my-output-1')]),
        html.Tr([html.Th('Summary'), html.Td(id='my-output-2')]),
        html.Tr([html.Th('Details'), html.Td(id='my-output-3')]),
        html.Tr([html.Th('Published'), html.Td(id='my-output-5')]),
        html.Tr([html.Th('Modified'), html.Td(id='my-output-6')]),
        html.Tr([html.Th('Withdrawn'), html.Td(id='my-output-7')])
    ]))
])

#Updating the Options everytime user changes the search value
@callback(
    Output(component_id='my-input', component_property='options'),
    Input(component_id='my-input', component_property='search_value')
)
def update_options(search_value):
    if not search_value:
        raise PreventUpdate
    global data 
    data = get_data(search_value)
    id_data = get_ID_data(data)
    return id_data

#Outputing the value to the table
@callback(
    Output(component_id='my-output', component_property='children'),
    Output(component_id='my-output-4', component_property='children'),
    Output(component_id='my-output-1', component_property='children'),
    Output(component_id='my-output-2', component_property='children'),
    Output(component_id='my-output-3', component_property='children'),
    Output(component_id='my-output-5', component_property='children'),
    Output(component_id='my-output-6', component_property='children'),
    Output(component_id='my-output-7', component_property='children'),
    Output(component_id='my-output-8', component_property='children'),
    Input(component_id='my-input', component_property='value')
)
def update_output_div(input_value):
    #Finding cwe ID from another table
    if input_value is not None and input_value != "":
        engine = create_engine("sqlite:///"+db)
        Session = sessionmaker(bind=engine)
        session = Session()
        try:
            # set table
            metadata = MetaData()
            cwe_table = Table('advisory_cwe', metadata, autoload_with=engine)
            # get data from table
            result = session.query(cwe_table).filter_by(advisory_id = input_value).all()
            result_str = ""
            for i in range(len(result)):
                result_str += "CWE-"+str(result[i][1])
                if i != len(result)-1:
                    result_str+=", "
        finally:
            session.close() # ensure session is closed
    
    tuple = []
    found = False
    global data
    for i in range(len(data)):
        if str(data[i][0]) == input_value:
            tuple = data[i]
            found = True
            break
    if found:
        return input_value, tuple[4] ,tuple[1], tuple[2], tuple[3], tuple[5], tuple[6], tuple[7], result_str
    else:
        return "","","","","","","","",""


#python gui_search_bar.py

if __name__ == '__main__':
    app.run(host="localhost", port=8080, debug=True)