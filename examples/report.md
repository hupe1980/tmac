# REST API Model
> 

## Data-Flow Diagram
![](dfd.png)

## Potential Risks
|ID|Risk|
|---|---|---|
|CAPEC-63@WebServer|Cross-Site Scripting (XSS) risk at WebServer|
|CAPEC-66@WebServer|SQL Injection risk at WebServer|


## User-Stories
|ID|User-Story|
|---|---|
|ASVS-5.1.3@CAPEC-63@WebServer|As a Security Champion I want all of the input which can affect control or data flow to be validated so that I can protect my application from malicious manipulation which could lead to unauthorised disclosure or loss of integrity.|
|ASVS-5.3.3@CAPEC-63@WebServer|As a Security Champion I want all of the output to be escaped so that I can protect my application against reflected, stored, and DOM based XSS.|
|ASVS-5.3.4@CAPEC-66@WebServer|As a Security Champion I want all data selection or database queries use parameterized queries so that my application is protected against database injection attacks.|
