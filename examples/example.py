#!/usr/bin/env python3

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.abspath(''), '..')))

import threatmodel as tm
import threatmodel.plus as tm_plus

model = tm.Model("REST Login Model")

user = tm_plus.Browser(model, "User")

login_process = tm.Process(
    model,
    "WebApi",
    machine=tm.Machine.VIRTUAL,
    technology=tm.Technology.WEB_SERVICE_REST,
)

login = tm.DataFlow(
    model,
    "Login",
    user,
    login_process,
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
    login_process,
    database ,
    protocol=tm.Protocol.SQL_ACCESS_PROTOCOL,
)

authenticate.sends(tm.Data("AuthenticateUserQuery"))
authenticate.receives(tm.Data("AuthenticateUserQueryResult"))

result = model.evaluate()

with open("example.pu","w+") as f:
    f.write(result.sequence_diagram())

print(result.risks_table(table_format=tm.TableFormat.GITHUB))
