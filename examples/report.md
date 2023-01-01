# REST API Model
> Sample description

## Data-Flow Diagram
![](dfd.png)

## Potential Risks
|ID|Category|Risk|
|---|---|---|
|[CAPEC-63@WebServer](#capec-63webserver)|Inject Unexpected Items|Cross-Site Scripting (XSS) risk at WebServer|
|[CAPEC-66@WebServer@DatabaseTraffic](#capec-66webserverdatabasetraffic)|Inject Unexpected Items|SQL Injection risk at WebServer against database Database via DatabaseTraffic|


## User Stories
|ID|Category|User Story|
|---|---|---|
|[ASVS-5.1.3@CAPEC-63@WebServer](#asvs-513capec-63webserver)|Input Validation|Verify that all input (HTML form fields, REST requests, URL parameters, HTTP headers, cookies, batch files, RSS feeds, etc) is validated using positive validation (allow lists).|
|[ASVS-5.3.3@CAPEC-63@WebServer](#asvs-533capec-63webserver)|Output Encoding and Injection Prevention|Verify that context-aware, preferably automated - or at worst, manual - output escaping protects against reflected, stored, and DOM based XSS.|
|[ASVS-13.2.2@CAPEC-63@WebServer](#asvs-1322capec-63webserver)|RESTful Web Service|As a security champion, I want all input to be validated against a JSON schema before being accepted so I can protect my application against injection attacks|
|[ASVS-5.1.4@CAPEC-63@WebServer](#asvs-514capec-63webserver)|Input Validation|Verify that structured data is strongly typed and validated against a defined schema including allowed characters, length and pattern (e.g. credit card numbers, e-mail addresses, telephone numbers, or validating that two related fields are reasonable, such as checking that suburb and zip/postcode match).|
|[ASVS-5.3.5@CAPEC-66@WebServer@DatabaseTraffic](#asvs-535capec-66webserverdatabasetraffic)|Output Encoding and Injection Prevention|Verify that where parameterized or safer mechanisms are not present, context-specific output encoding is used to protect against injection attacks, such as the use of SQL escaping to protect against SQL injection.|
|[ASVS-5.3.4@CAPEC-66@WebServer@DatabaseTraffic](#asvs-534capec-66webserverdatabasetraffic)|Output Encoding and Injection Prevention|Verify that data selection or database queries (e.g. SQL, HQL, ORM, NoSQL) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from database injection attacks.|
|[ASVS-13.3.1@CAPEC-63@WebServer](#asvs-1331capec-63webserver)|SOAP Web Service|Verify that XSD schema validation takes place to ensure a properly formed XML document, followed by validation of each input field before any processing of that data takes place.|


## Risk Details
### CAPEC-63@WebServer
An adversary embeds malicious scripts in content that will be served to web browsers. The goal of the attack is for the target software, the client-side browser, to execute the script with the users' privilege level. An attack of this type exploits a programs' vulnerabilities that are brought on by allowing remote hosts to execute code and scripts. Web browsers, for example, have some simple security controls in place, but if a remote attacker is allowed to execute scripts (through injecting them in to user-generated content like bulletin boards) then these controls may be bypassed. Further, these attacks are very difficult for an end user to detect.

**Prerequisites**:
- Target client software must be a client that allows scripting communication from remote hosts, such as a JavaScript-enabled Web Browser.

**Risk**:\
⚠ Cross-Site Scripting (XSS) risk at WebServer

**Mitigations**:
- Escape output against XSS: [ASVS-5.3.3@CAPEC-63@WebServer](#asvs-533capec-63webserver)
- Enforce schema on XML structure/field: [ASVS-13.3.1@CAPEC-63@WebServer](#asvs-1331capec-63webserver)
- Enforce JSON schema before processing: [ASVS-13.2.2@CAPEC-63@WebServer](#asvs-1322capec-63webserver)
- Enforce schema on type/contents of structured data: [ASVS-5.1.4@CAPEC-63@WebServer](#asvs-514capec-63webserver)
- Whitelist all external (HTTP) input: [ASVS-5.1.3@CAPEC-63@WebServer](#asvs-513capec-63webserver)

**References**:
- https://capec.mitre.org/data/definitions/63.html
- https://cwe.mitre.org/data/definitions/79.html
- https://cwe.mitre.org/data/definitions/20.html

---
### CAPEC-66@WebServer@DatabaseTraffic
This attack exploits target software that constructs SQL statements based on user input. An attacker crafts input strings so that when the target software constructs SQL statements based on the input, the resulting SQL statement performs actions other than those the application intended. SQL Injection results from failure of the application to appropriately validate input.

**Prerequisites**:
- SQL queries used by the application to store, retrieve or modify data.
- User-controllable input that is not properly validated by the application as part of SQL queries.

**Risk**:\
⚠ SQL Injection risk at WebServer against database Database via DatabaseTraffic

**Mitigations**:
- Encode output context-specifically: [ASVS-5.3.5@CAPEC-66@WebServer@DatabaseTraffic](#asvs-535capec-66webserverdatabasetraffic)
- Lock/precompile queries (parameterization) to avoid injection attacks: [ASVS-5.3.4@CAPEC-66@WebServer@DatabaseTraffic](#asvs-534capec-66webserverdatabasetraffic)

**References**:
- https://capec.mitre.org/data/definitions/66.html
- https://cwe.mitre.org/data/definitions/89.html
- https://cwe.mitre.org/data/definitions/1286.html

---


## User Story Details
### ASVS-5.1.3@CAPEC-63@WebServer
Verify that all input (HTML form fields, REST requests, URL parameters, HTTP headers, cookies, batch files, RSS feeds, etc) is validated using positive validation (allow lists).

**Feature Name**: Whitelist all external (HTTP) input

**User Story**:\
Verify that all input (HTML form fields, REST requests, URL parameters, HTTP headers, cookies, batch files, RSS feeds, etc) is validated using positive validation (allow lists).


**References**:
- https://owasp-top-10-proactive-controls-2018.readthedocs.io/en/latest/c5-validate-all-inputs.html
- https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/
- https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/20.html

---
### ASVS-5.3.3@CAPEC-63@WebServer
Verify that context-aware, preferably automated - or at worst, manual - output escaping protects against reflected, stored, and DOM based XSS.

**Feature Name**: Escape output against XSS

**User Story**:\
Verify that context-aware, preferably automated - or at worst, manual - output escaping protects against reflected, stored, and DOM based XSS.


**References**:
- https://owasp-top-10-proactive-controls-2018.readthedocs.io/en/latest/c4-encode-escape-data.html
- https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting.html
- https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/79.html

---
### ASVS-13.2.2@CAPEC-63@WebServer
Verify that JSON schema validation is in place and verified before accepting input.

**Feature Name**: Enforce JSON schema before processing

**User Story**:\
As a security champion, I want all input to be validated against a JSON schema before being accepted so I can protect my application against injection attacks


**Scenarios**:\
**Use of input validation framework**:
```Gherkin
Given functions processing externally provided JSON inputs
When I parse or encode such inputs
Then I use an `input validation framework` to reduce exposure to parsing-related threats
```
**Input conformance to specifications**:
```Gherkin
Given functions processing externally provided JSON input
When I parse or encode such inputs
Then I validate that inputs are conforming to specification
```
**Conversion of input type to expected data type**:
```Gherkin
Given functions processing externally provided JSON input
When I parse or encode such inputs
Then I convert input into the expected data type
And check that input value is within an expected range of allowable values
```


**References**:
- https://cheatsheetseries.owasp.org/cheatsheets/REST_Assessment_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/20.html

---
### ASVS-5.1.4@CAPEC-63@WebServer
Verify that structured data is strongly typed and validated against a defined schema including allowed characters, length and pattern (e.g. credit card numbers, e-mail addresses, telephone numbers, or validating that two related fields are reasonable, such as checking that suburb and zip/postcode match).

**Feature Name**: Enforce schema on type/contents of structured data

**User Story**:\
Verify that structured data is strongly typed and validated against a defined schema including allowed characters, length and pattern (e.g. credit card numbers, e-mail addresses, telephone numbers, or validating that two related fields are reasonable, such as checking that suburb and zip/postcode match).


**References**:
- https://owasp-top-10-proactive-controls-2018.readthedocs.io/en/latest/c5-validate-all-inputs.html
- https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/
- https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/20.html

---
### ASVS-13.3.1@CAPEC-63@WebServer
Verify that XSD schema validation takes place to ensure a properly formed XML document, followed by validation of each input field before any processing of that data takes place.

**Feature Name**: Enforce schema on XML structure/field

**User Story**:\
Verify that XSD schema validation takes place to ensure a properly formed XML document, followed by validation of each input field before any processing of that data takes place.


**References**:
- https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection.html
- https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/20.html

---
### ASVS-5.3.5@CAPEC-66@WebServer@DatabaseTraffic
Verify that where parameterized or safer mechanisms are not present, context-specific output encoding is used to protect against injection attacks, such as the use of SQL escaping to protect against SQL injection.

**Feature Name**: Encode output context-specifically

**User Story**:\
Verify that where parameterized or safer mechanisms are not present, context-specific output encoding is used to protect against injection attacks, such as the use of SQL escaping to protect against SQL injection.


**References**:
- https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html
- https://cwe.mitre.org/data/definitions/89.html

---
### ASVS-5.3.4@CAPEC-66@WebServer@DatabaseTraffic
Verify that data selection or database queries (e.g. SQL, HQL, ORM, NoSQL) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from database injection attacks.

**Feature Name**: Lock/precompile queries (parameterization) to avoid injection attacks

**User Story**:\
Verify that data selection or database queries (e.g. SQL, HQL, ORM, NoSQL) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from database injection attacks.


**References**:
- https://owasp-top-10-proactive-controls-2018.readthedocs.io/en/latest/c3-secure-database-access.html
- https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html
- https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/89.html

---
