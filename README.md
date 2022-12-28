# tmac
> Agile Threat Modeling as Code

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

model = Model("Login Model")

user = Browser(model, "User")

web_server = Process(
    model, "WebServer",
    machine=Machine.VIRTUAL,
    technology=Technology.WEB_WEB_APPLICATION,
)

login = DataFlow(
    model, "Login",
    source=user,
    destination=web_server,
    protocol=Protocol.HTTPS,
)

login.transfers(
    "UserCredentials",
    confidentiality=Score.HIGH,
    integrity=Score.HIGH,
    availability=Score.HIGH,
)

database = Database(
    model, "Database",
    machine=Machine.VIRTUAL,
)

authenticate = DataFlow(
    model, "Authenticate",
    source=web_server,
    destination=database,
    protocol=Protocol.SQL,
)

user_details = Asset(
    model, "UserDetails",
    confidentiality=Score.HIGH,
    integrity=Score.HIGH,
    availability=Score.HIGH,
)

authenticate.transfers(user_details)

print(model.risks_table(table_format=TableFormat.GITHUB))
```
Output:
| SID                 | Severity   | Category                   | Name                                | Affected   | Treatment   |
|---------------------|------------|----------------------------|-------------------------------------|------------|-------------|
| CAPEC-63@WebServer  | elevated   | Inject Unexpected Items    | Cross-Site Scripting (XSS)          | WebServer  | mitigated   |
| CAPEC-100@WebServer | high       | Manipulate Data Structures | Overflow Buffers                    | WebServer  | unchecked   |
| CAPEC-101@WebServer | elevated   | Inject Unexpected Items    | Server Side Include (SSI) Injection | WebServer  | mitigated   |
| CAPEC-62@WebServer  | high       | Subvert Access Control     | Cross Site Request Forgery          | WebServer  | unchecked   |
| CAPEC-66@WebServer  | elevated   | Inject Unexpected Items    | SQL Injection                       | WebServer  | unchecked   |
|...|...|...|...|...|...|

## Jupyter Threatbooks
> Threat modeling with jupyter notebooks

![threatbook.png](https://github.com/hupe1980/tmac/raw/main/.assets/threatbook.png)

## Generating Diagrams
```python
model.data_flow_diagram()
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