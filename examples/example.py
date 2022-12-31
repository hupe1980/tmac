#!/usr/bin/env python3

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.abspath(""), "..")))

from tmac import (
    Machine,
    Model,
    Process,
    Protocol,
    Score,
    TableFormat,
    Technology,
)  # noqa: E402
from tmac.plus import Database, User  # noqa: E402

model = Model("REST API Model")

user = User(model, "User")

web_server = Process(
    model,
    "WebServer",
    machine=Machine.VIRTUAL,
    technology=Technology.WEB_APPLICATION,
)

database = Database(
    model,
    "Database",
    machine=Machine.VIRTUAL,
)

web_traffic = user.add_data_flow(
    "WebTraffic",
    destination=web_server,
    protocol=Protocol.HTTPS,
)

web_traffic.transfers(
    "UserCredentials",
    confidentiality=Score.HIGH,
    integrity=Score.HIGH,
    availability=Score.HIGH,
)

database_traffic = web_server.add_data_flow(
    "DatabaseTraffic",
    destination=database,
    protocol=Protocol.SQL,
)

database_traffic.transfers(
    "UserDetails",
    confidentiality=Score.HIGH,
    integrity=Score.HIGH,
    availability=Score.HIGH,
)

print(model.create_risks_table(table_format=TableFormat.GITHUB)+"\n")
print(model.create_backlog_table()+"\n")

model.create_data_flow_diagram(auto_view=False)

model.create_report()

# print(model.otm)
