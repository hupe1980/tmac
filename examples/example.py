#!/usr/bin/env python3

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.abspath(""), "..")))

from tmac import (
    Asset,
    DataFlow,
    Machine,
    Model,  
    Process,
    Protocol,
    Score,
    TableFormat,
    Technology,
) # noqa: E402
from tmac.plus import Browser, Database  # noqa: E402

model = Model("REST Login Model")

user = Browser(model, "User")

web_server = Process(
    model,
    "WebServer",
    machine=Machine.VIRTUAL,
    technology=Technology.WEB_APPLICATION,
)

login = user.add_data_flow("Login", destination=web_server, protocol=Protocol.HTTPS)

login.transfers(
    "UserCredentials",
    confidentiality=Score.HIGH,
    integrity=Score.HIGH,
    availability=Score.HIGH,
)

database = Database(
    model,
    "Database",
    machine=Machine.VIRTUAL,
)

authenticate = DataFlow(
    model,
    "Authenticate",
    source=web_server,
    destination=database,
    protocol=Protocol.SQL,
)

user_details = Asset(
    model,
    "UserDetails",
    confidentiality=Score.HIGH,
    integrity=Score.HIGH,
    availability=Score.HIGH,
)

authenticate.transfers(user_details)

print(model.risks_table(table_format=TableFormat.GITHUB))

model.mitigate_risk(
    "CAPEC-100@WebServer",
    name="BoundChecks",
    risk_reduction=80,
)

print(model.risks_table(table_format=TableFormat.GITHUB))

model.data_flow_diagram(auto_view=False)

# print(model.otm)
