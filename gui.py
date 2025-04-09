# -*- coding: utf-8 -*-
import dash
from dash import dcc, html
import dash_bootstrap_components as dbc
from dash.dependencies import Input, Output
from gui_project_grid import set_layout
from datetime import datetime

# Initialize the app
gui = dash.Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP]) # prevent_initial_callbacks = True

# Greeting function
def get_greeting():
    now = datetime.now().hour
    if 0 <= now < 12:
        return "Good morning"
    elif 12 <= now < 18:
        return "Good afternoon"
    else:
        return "Good evening"

# Navigation bar
navbar = dbc.Navbar(
    dbc.Container(fluid=True, children=[
        
        # Brand
        dbc.NavbarBrand("Vulnerability Reporter", href="/", className="ms-2 me-4"),

        # Search Bar (a temporary placeholder, waiting to be merged with real features)
        dbc.Row([
            dbc.Col(
                dcc.Input(
                    type="text",
                    disabled=True,
                    placeholder="Search (coming soon...)",
                    className="form-control text-muted",
                    style={
                        "width": "500px",
                        "backgroundColor": "#e9ecef",
                        "textAlign": "center"
                    }
                ),
                width="auto"
            )
        ],
        align="center",
        className="mx-auto"),  

        # Greeting message & login button
        dbc.Row([
            dbc.Col(html.Span(f"{get_greeting()}, visitor.", className="navbar-text text-white"), width="auto"),
            dbc.Col(
                dbc.Button("Log In", color="danger", size="sm", href="/login",
                           style={"height": "38px", "lineHeight": "20px", "padding": "8px 16px"}),
                width="auto"
            )
        ],
        align="center",
        className="ms-auto g-2 flex-nowrap")
    ]),
    color="#2d3436",
    dark=True,
    className="mb-0",
    sticky="top",
    style={
        "marginBottom": "0",
        "borderBottom": "none",
        "boxShadow": "0 2px 4px rgba(0,0,0,0.1)"
    }
)

# Footer
footer = html.Footer(
    html.Div([
        html.Hr(),
        html.P("This dashboard updates at 3:00 pm daily to reflect the latest data from GitHub's security advisories.", className="text-center text-muted"),
        html.P("2025 Vulnerability Reporter. COMP354 Group-3. All rights reserved.", className="text-center text-muted")
    ]),
    style={
        "backgroundColor": "#f8f9fa",
        "color": "#666666",
        "borderTop": "1px solid #ddd" 
    }
)

# Defines initial layout
gui.layout = html.Div([
    dcc.Location(id='url', refresh=False),
    navbar,
    html.Div(id='page-content', style={"minHeight": "80vh"}), 
    footer
])

# Update page content when selected | Allow_duplicate = True in output, prevent_initial_call = True after input
@gui.callback(Output("page-content", "children"), Input("url", "pathname"))
def display_page(pathname):
    if pathname == "/":
        return home_page
    elif pathname == "/cve_table":
        return cve_table
    elif pathname == "/cwe_table": # add pages below this conditional for top 10 CVE and CWE
        return cwe_table
    elif pathname == "/login":
        return login_page
    else:
        return error_page 

# Home Page
home_page = html.Div(
    children=[
        dbc.Container([
            html.H1("Welcome to the Vulnerability Reporter", style={"color": "#2d3436", "textShadow": "0 1px 2px rgba(255,255,255,0.5)", "fontWeight": "bold"}),
            html.P("Gain insights into software security by exploring real-world vulnerabilities (CVEs) and their underlying weakness patterns (CWEs), based on GitHub's Advisory Database.", 
                    style={"color": "#f8f9fa", "fontSize": "18px", "lineHeight": "1.6", "fontStyle": "italic"
            }),
            html.Hr(),

            dbc.Row([
                
                # CVE card
                dbc.Col(
                    dbc.Card([
                        dbc.CardBody([
                            html.H4("Explore CVEs", className="card-title", 
                                    style={"color": "#ffffff", "backgroundColor": "#2d3436", "padding": "12px"}),
                            html.P("Discover detailed information about publicly disclosed software vulnerabilities. Sort and filter by severity, date, or affected components to support your security analysis and awareness.", 
                                    style={"color": "#4a4a4a"}),
                            dbc.Button("Go to CVE Table", color="primary", href="/cve_table",
                                    style={"backgroundColor": "#007bff", "border": "none", "color": "#ffffff"})
                        ])
                    ], style={"border": "1px solid #eee", "backgroundColor": "rgba(255,255,255,0.9)"}),
                    md=6
                ),
                
                # CWE card
                dbc.Col(
                    dbc.Card([
                        dbc.CardBody([
                            html.H4("Explore CWEs", className="card-title", 
                                    style={"color": "#ffffff", "backgroundColor": "#2d3436", "padding": "12px"}),
                            html.P("Understand the root causes behind software vulnerabilities through structured weakness types. Browse common patterns, frequencies, and links to real-world CVEs.", 
                                    style={"color": "#4a4a4a"}),
                            dbc.Button("Go to CWE Table", color="primary", href="/cwe_table",
                                    style={"backgroundColor": "#007bff", "border": "none", "color": "#ffffff"})
                        ])
                    ], style={"border": "1px solid #eee", "backgroundColor": "rgba(255,255,255,0.9)"}),
                    md=6
                )
            ], className="mt-4"),
        ])
    ], style={"backgroundImage": "url('/assets/software-vulnerability-blog_1316x584.png')",
              "backgroundSize": "cover",
              "backgroundPosition": "center",
              "minHeight": "100vh", 
              "marginTop": "-24px", 
              "paddingTop": "100px", 
              "paddingBottom": "0"
        }
)

# CVE page
cve_table = html.Div([
    html.H1('CVE'),
    set_layout("cve")
])

# CWE page
cwe_table = html.Div([
    html.H1('CWE'),
    set_layout("cwe")
])

# Login page (a placeholder only, waiting to be merged with real features)
login_page = dbc.Container([
    html.H1("Login", className="mt-4"),
    html.P("This is a placeholder page for the login form. The login feature will be implemented here."),
    html.Hr(),
    dbc.Alert("Login functionality coming soon!", color="warning")
])

# Error page
error_page = dbc.Container([
    html.Div([
        html.H1("404", className="text-danger display-3"),
        html.Img(src="https://http.cat/404", height="250px", className="mb-3"),
        html.Hr(),
        html.H4("Page Not Found"),
        html.P(f"The page does not exist."),
        html.P("Please check the URL or return to the homepage."),
        dbc.Button("Return", color="primary", href="/", className="mt-3")
    ], className="text-center p-5")
])

# Run the app
if __name__ == '__main__':
    gui.run(host='localhost', port=8080, debug=False) # enable debug mode to see errors