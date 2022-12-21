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
web_server.add_controls(tm.Control.INPUT_VALIDATION, tm.Control.INPUT_SANITIZING)

login = tm.DataFlow(
    model,
    "Login",
    user,
    web_server,
    protocol=tm.Protocol.HTTPS,
)

login.sends(tm.Data("LoginRequest"))
login.receives(tm.Data("LoginResponse"))

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

authenticate.sends(tm.Data("AuthenticateUserQuery"))
authenticate.receives(tm.Data("AuthenticateUserQueryResult"))

result = model.evaluate()

print(result.risks_table(table_format=tm.TableFormat.GITHUB))

result.data_flow_diagram(auto_view=False)

