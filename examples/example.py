import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.abspath(''), '..')))

from threatmodel import Model, Process, Machine, Technology, Data, DataFlow, DataStore, Protocol

model = Model("Demo Model")

pii = Data("PII")

server = Process(
    model,
    "Server",
    machine=Machine.VIRTUAL,
    technology=Technology.WEB_SERVER,
    environment_variables=True,
)

server.processes(pii)

database = DataStore(
    model,
    "Database",
    machine=Machine.VIRTUAL,
    technology=Technology.DATABASE,
    environment_variables=False,
)

database.stores(pii)

crud = DataFlow(
    model,
    "CRUD",
    server,
    database,
    protocol=Protocol.SQL_ACCESS_PROTOCOL
)

crud.sends(pii)
crud.receives(pii)

result = model.evaluate()

print(result.risks)
