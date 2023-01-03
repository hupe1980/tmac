# tmac
> Agile Threat Modeling as Code
- Close to the code - close to developers

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

from tmac import (
    Model,
    Process,
    Protocol,
    Score,
    TableFormat,
    Technology,
    TrustBoundary,
)
from tmac.plus import Browser, Database

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

print(model.risks_table(table_format=TableFormat.GITHUB))
```
Output:
| ID                                 | Category                | Risk                                                                            | Treatment   |
|------------------------------------|-------------------------|---------------------------------------------------------------------------------|-------------|
| CAPEC-62@WebServer@WebTraffic      | Subvert Access Control  | Cross-Site Request Forgery (CSRF) risk at WebServer via WebTraffic from Browser | in-progress |
| CAPEC-63@WebServer                 | Inject Unexpected Items | Cross-Site Scripting (XSS) risk at WebServer                                    | accepted    |
| CAPEC-66@WebServer@DatabaseTraffic | Inject Unexpected Items | SQL Injection risk at WebServer against database Database via DatabaseTraffic   | mitigated   |
|...|...|...|...|
```python
print(model.create_backlog_table(table_format=TableFormat.GITHUB))
```
Output:
| ID                                            | Category                                     | User Story                                                                                                                                                                                                                                                         | State       |
|-----------------------------------------------|----------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------|
| ASVS-13.2.3@CAPEC-62@WebServer@WebTraffic     | RESTful Web Service                          | Verify that RESTful web services that utilize cookies are protected from Cross-Site Request Forgery via the use of at least one or more of the following: double submit cookie pattern, CSRF nonces, or Origin request header checks.                              | draft       |
| ASVS-5.3.5@CAPEC-66@WebServer@DatabaseTraffic | Output Encoding and Injection Prevention     | Verify that where parameterized or safer mechanisms are not present, context-specific output encoding is used to protect against injection attacks, such as the use of SQL escaping to protect against SQL injection.                                              | closed      |
| ASVS-1.2.3@CAPEC-62@WebServer@WebTraffic      | Authentication Architecture                  | Verify that the application uses a single vetted authentication mechanism that is known to be secure, can be extended to include strong authentication, and has sufficient logging and monitoring to detect account abuse or breaches.                             | in-progress |
|...|...|...|...|
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

## Custom ThreatLibrary
```python
from tmac import Model, ThreatLibrary

lib = ThreatLibrary()

lib.add_threat("""... your custom threats ...""")

model = Model("Demo Model", threat_library=lib)
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