#!/usr/bin/env python3

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.abspath(""), "..")))

from tmac import (
    Model,
    Process,
    Protocol,
    Score,
    TableFormat,
    Technology,
    TrustBoundary,
)  # noqa: E402
from tmac.plus import Browser, Database  # noqa: E402

model = Model("Demo Model", description="Sample description")

internet = TrustBoundary(model, "Internet")
dmz = TrustBoundary(model, "DMZ")
intranet = TrustBoundary(model, "Intranet")

browser = Browser(model, "Browser", trust_boundary=internet)

web_server = Process(
    model,
    "WebServer",
    technology=Technology.WEB_APPLICATION,
    trust_boundary=dmz,
)

database = Database(
    model,
    "Database",
    trust_boundary=intranet,
)

web_traffic = browser.add_data_flow(
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

model.update_user_story("ASVS-5.3.3@CAPEC-63@WebServer", "in progress")

print(model.create_risks_table(table_format=TableFormat.GITHUB) + "\n")
print(model.create_backlog_table() + "\n")

model.create_data_flow_diagram(auto_view=False)

model.create_report()

# print(model.otm)
