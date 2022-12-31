# {{ model.name }}
> {{ model.description }}

## Data-Flow Diagram
![](dfd.png)

## Potential Risks
|ID|Risk|
|---|---|
{% for risk in model.risks -%}
|{{ risk.id }}|{{ risk.text }}|
{% endfor %}

## User-Stories
|ID|User-Story|
|---|---|
{% for story in model.user_stories -%}
|{{ story.id }}|{{ story.text }}|
{% endfor %}
