# Security Policy

Binary Refinery is intended for **static** malware analysis,
but it is nevertheless recommended to never analyze malware outside a sufficiently secured, preferably virtual, environment.
That said refinery units should be robust against any input and:
- Units should never perform uncontrolled execution of any part of the input.
- Units should never write part of the input anywhere to disk, not even temporarily, except when this is their explicit given task.

Should you identify any security vulnerabilities or violations of these principles, please file a 
[bug report](https://github.com/binref/refinery/issues/new?assignees=huettenhain&labels=bug&template=bug_report.md).
