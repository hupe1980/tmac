# {{ model.name }}
> {{ model.description }}

## Data-Flow Diagram
![](dfd.png)

## Potential Risks
|ID|Category|Risk|Treatment|
|---|---|---|---|
{% for risk in model.risks -%}
|[{{ risk.id }}](#{{ risk.id|lower|replace("@", "")|replace(".", "") }})|{{ risk.category }}|{{ risk.text }}|{{ risk.treatment.state }}|
{% endfor %}

## User Stories
|ID|Category|User Story|State|
|---|---|---|---|
{% for story in model.user_stories -%}
|[{{ story.id }}](#{{ story.id|lower|replace("@", "")|replace(".", "") }})|{{ story.sub_category }}|{{ story.text }}|{{ story.state }}|
{% endfor %}

## Risk Details
{% for risk in model.risks -%}
### {{ risk.id }} 
> {{ risk.description }}

**Prerequisites**:
{% for prerequisite in risk.prerequisites -%}
- {{ prerequisite }}
{% endfor %}
**Risk**:\
⚠ {{ risk.text }} [{{ risk.treatment.state }}]

**Mitigations**:
{% for story in risk.user_stories -%}
- {{ story.feature_name }}: [{{ story.id }}](#{{ story.id|lower|replace("@", "")|replace(".", "") }})
{% endfor %}
**References**:
{% for reference in risk.references -%}
- {{ reference }}
{% endfor %}
---
{% endfor %}

## User Story Details
{% for story in model.user_stories -%}
### {{ story.id }} 
> {{ story.description }} 

**Feature Name**: {{ story.feature_name}}

**User Story**:\
{{ story.text }} [{{ story.state }}]

{% if story.scenarios|length > 0 %}
**Scenarios**:\
{% for key, value in story.scenarios.items() -%}
**{{ key }}**:
```Gherkin
{{ value }}
```
{% endfor %}
{% endif %}
**References**:
{% for reference in story.references -%}
- {{ reference }}
{% endfor %}
---
{% endfor %}
