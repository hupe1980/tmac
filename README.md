# threatmodel
> Agile Threat Modeling as Code

## Install
```bash
pip install threatmodel
```

## How to use
```bash
python3 threatmodel.py
```

```python
#!/usr/bin/env python3

import threatmodel as tm
import threatmodel.plus as tm_plus

model = tm.Model("Login Model")

user = tm_plus.Browser(model, "User")

web_server = tm.Process(
    model, "WebServer",
    machine=tm.Machine.VIRTUAL,
    technology=tm.Technology.WEB_WEB_APPLICATION,
)

login = tm.DataFlow(
    model, "Login",
    source=user,
    destination=web_server,
    protocol=tm.Protocol.HTTPS,
)

login.transfers(
    "UserCredentials",
    confidentiality=tm.Score.HIGH,
    integrity=tm.Score.HIGH,
    availability=tm.Score.HIGH,
)

database = tm.DataStore(
    model, "Database",
    machine=tm.Machine.VIRTUAL,
    technology=tm.Technology.DATABASE,
)

authenticate = tm.DataFlow(
    model, "Authenticate",
    source=web_server,
    destination=database,
    protocol=tm.Protocol.SQL,
)

user_details = tm.Asset(
    model, "UserDetails",
    confidentiality=tm.Score.HIGH,
    integrity=tm.Score.HIGH,
    availability=tm.Score.HIGH,
)

authenticate.transfers(user_details)

print(model.risks_table(table_format=tm.TableFormat.GITHUB))
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

## Jupyter Threatbook
> Threatmodeling with jupyter notebooks

![threatbook.png](https://github.com/hupe1980/threatmodel/raw/main/.assets/threatbook.png)

## Generating Diagrams
```python
model.data_flow_diagram()
```
![threatbook.png](https://github.com/hupe1980/threatmodel/raw/main/.assets/data-flow-diagram.png)

## High level elements (threatmodel/plus*)
```python
import threatmodel.plus_aws as tm_plus_aws

# ...

alb = tm_plus_aws.ApplicationLoadBalancer(model, "ALB", waf=True)

```

## Custom threatlib
```python
import threatmodel as tm

threatlib = tm.Threatlib()

threatlib.add_threat("""... your custom threats ...""")

model = tm.Model("Demo Model", threatlib=threatlib)
```
## Examples

See more complete [examples](https://github.com/hupe1980/threatmodel/tree/master/examples).

## Prior work and other related projects
- [pytm](https://github.com/izar/pytm) - A Pythonic framework for threat modeling
- [threagile](https://github.com/Threagile/threagile) - Agile Threat Modeling Toolkit
- [cdk-threagile](https://github.com/hupe1980/cdk-threagile) - Agile Threat Modeling as Code
- [OpenThreatModel](https://github.com/iriusrisk/OpenThreatModel) - OpenThreatModel

## License

[MIT](LICENSE)