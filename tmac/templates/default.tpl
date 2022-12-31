# {{ model.name }}
> {{ model.description }}

## Data-Flow Diagram
![](dfd.png)

## Potential Risks
|ID|Risk|
|---|---|
{% for risk in model.risks -%}
|[{{ risk.id }}](#{{ risk.id|lower }})|{{ risk.text }}|
{% endfor %}

## User Stories
|ID|User Story|
|---|---|
{% for story in model.user_stories -%}
|[{{ story.id }}](#{{ story.id|lower }})|{{ story.text }}|
{% endfor %}

## Risk Details
{% for risk in model.risks -%}
### {{ risk.id }}
{{ risk.description }}

**Prerequisites**:
{% for prerequisite in risk.prerequisites -%}
- {{ prerequisite }}
{% endfor %}
**Risk**:\
⚠ {{ risk.text }}

**Mitigations**:
{% for story in risk.user_stories -%}
- {{ story.feature_name }}: [{{ story.id }}](#{{ story.id|lower}})
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
{{ story.description }}

#### User Story
**Feature Name**: {{ story.feature_name}}

**Story**:\
{{ story.text }}

**References**:
{% for reference in story.references -%}
- {{ reference }}
{% endfor %}
---
{% endfor %}
