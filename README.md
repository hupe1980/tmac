# tmac
> Agile Threat Modeling as Code
- Close to the code - close to developers
- Optimized for jupyter notebooks
- Generates data-flow diagrams

## Install
```bash
pip install tmac
```

## How to use
```bash
python3 tmac.py
```

```python
#!/usr/bin/env python3

from tmac import (Asset, DataFlow, Machine, Model, Process, Protocol, 
                    Score, TableFormat, Technology)
from tmac.plus import Browser, Database

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

print(model.risks_table(table_format=TableFormat.GITHUB))
```
Output:
| ID                 | Risk                                         |
|--------------------|----------------------------------------------|
| CAPEC-63@WebServer | Cross-Site Scripting (XSS) risk at WebServer |
| CAPEC-66@WebServer | SQL Injection risk at WebServer              |
|...|...|
```python
print(model.create_backlog_table(table_format=TableFormat.GITHUB))
```
Output:
| ID                            | User Story                                                                                                                                                                                                                              |
|-------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| ASVS-5.1.3@CAPEC-63@WebServer | As a Security Champion I want all of the input which can affect control or data flow to be validated so that I can protect my application from malicious manipulation which could lead to unauthorised disclosure or loss of integrity. |
| ASVS-5.3.3@CAPEC-63@WebServer | As a Security Champion I want all of the output to be escaped so that I can protect my application against reflected, stored, and DOM based XSS.                                                                                        |
| ASVS-5.3.4@CAPEC-66@WebServer | As a Security Champion I want all data selection or database queries use parameterized queries so that my application is protected against database injection attacks.                                                                  |
## Jupyter Threatbooks
> Threat modeling with jupyter notebooks

![threatbook.png](https://github.com/hupe1980/tmac/raw/main/.assets/threatbook.png)

## Generating Diagrams
```python
model.create_data_flow_diagram()
```
![threatbook.png](https://github.com/hupe1980/tmac/raw/main/.assets/data-flow-diagram.png)

## High level elements (tmac/plus*)
```python
from tmac.plus_aws import ApplicationLoadBalancer

# ...

alb = ApplicationLoadBalancer(model, "ALB", waf=True)

```

## Custom threatlib
```python
from tmac import Model, Threatlib

threatlib = Threatlib()

threatlib.add_threat("""... your custom threats ...""")

model = Model("Demo Model", threatlib=threatlib)
```
## Examples

See more complete [examples](https://github.com/hupe1980/tmac/tree/master/examples).

## Prior work and other related projects
- [pytm](https://github.com/izar/pytm) - A Pythonic framework for threat modeling
- [threagile](https://github.com/Threagile/threagile) - Agile Threat Modeling Toolkit
- [cdk-threagile](https://github.com/hupe1980/cdk-threagile) - Agile Threat Modeling as Code
- [OpenThreatModel](https://github.com/iriusrisk/OpenThreatModel) - OpenThreatModel

## License

[MIT](LICENSE)