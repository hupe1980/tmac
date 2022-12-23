#!/usr/bin/env python3

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.abspath(''), '..')))

import threatmodel as tm
import threatmodel.plus as tm_plus

model = tm.Model("REST Login Model")

user = tm_plus.Browser(model, "User")
 
web_server = tm.Process(
    model,
    "WebServer",
    machine=tm.Machine.VIRTUAL,
    technology=tm.Technology.WEB_APPLICATION,
)

login = tm.DataFlow(
    model,
    "Login",
    user,
    web_server,
    protocol=tm.Protocol.HTTPS,
)

login.transfers(tm.Data("UserCredentials"))

database = tm.DataStore(
    model,
    "Database",
    machine=tm.Machine.VIRTUAL,
    technology=tm.Technology.DATABASE,
)

authenticate= tm.DataFlow(
    model,
    "Authenticate",
    web_server,
    database ,
    protocol=tm.Protocol.SQL,
)

authenticate.transfers(tm.Data("AuthenticateQuery"))

print(model.risks_table(table_format=tm.TableFormat.GITHUB))

model.mitigate_risk("CAPEC-100@WebServer", tm.Mitigation(model, "DEMO"))

print(model.risks_table(table_format=tm.TableFormat.GITHUB))

model.data_flow_diagram(auto_view=False)

# print(model.otm)

