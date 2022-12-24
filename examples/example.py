#!/usr/bin/env python3

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.abspath(''), '..')))

import threatmodel.plus as tm_plus
import threatmodel as tm


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

login.transfers("UserCredentials", tm.Confidentiality.HIGH, tm.Integrity.HIGH, tm.Availability.HIGH)

database = tm.DataStore(
    model,
    "Database",
    machine=tm.Machine.VIRTUAL,
    technology=tm.Technology.DATABASE,
)

authenticate = tm.DataFlow(
    model,
    "Authenticate",
    web_server,
    database,
    protocol=tm.Protocol.SQL,
)

user_details = tm.Asset(model, "UserDetails", tm.Confidentiality.HIGH, tm.Integrity.HIGH, tm.Availability.HIGH)

authenticate.transfers(user_details)

print(model.risks_table(table_format=tm.TableFormat.GITHUB))

model.mitigate_risk("CAPEC-100@WebServer", name = "BoundChecks", risk_reduction = 80)

print(model.risks_table(table_format=tm.TableFormat.GITHUB))

model.data_flow_diagram(auto_view = False)

#print(model.otm)
