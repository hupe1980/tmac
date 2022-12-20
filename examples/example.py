import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from threatmodel import Model, Process, Machine, Data, DataStore

model = Model("Demo Model")

pii = Data("PII")

server = Process(
    model, 
    "Server", 
    machine=Machine.SERVERLESS,
    environment_variables=True,
)

server.processes(pii)

database = DataStore(
    model,
    "Database",
    machine=Machine.SERVERLESS,
    environment_variables=False, 
)

database.stores(pii)


result = model.evaluate()

print(result.risks)