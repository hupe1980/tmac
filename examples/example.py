#!/usr/bin/env python3

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.abspath(''), '..')))

import threatmodel as tm
import threatmodel.plus as plus
import threatmodel.plus_aws as plus_aws


model = tm.Model("Demo Model")

pii = tm.Data("PII")

browser = plus.Browser(model, "Browser")

alb = plus_aws.ApplicationLoadBalancer(model, "ALB", waf=True)

server = tm.Process(
    model,
    "Server",
    machine=tm.Machine.VIRTUAL,
    technology=tm.Technology.WEB_SERVER,
    environment_variables=True,
)

server.processes(pii)

database = tm.DataStore(
    model,
    "Database",
    machine=tm.Machine.VIRTUAL,
    technology=tm.Technology.DATABASE,
    environment_variables=False,
)

database.stores(pii)

crud = tm.DataFlow(
    model,
    "CRUD",
    server,
    database,
    protocol=tm.Protocol.SQL_ACCESS_PROTOCOL
)

crud.sends(pii)
crud.receives(pii)

result = model.evaluate()

print(result.risks_table(table_format=tm.TableFormat.GITHUB))
