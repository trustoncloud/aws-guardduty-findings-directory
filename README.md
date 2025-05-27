# aws-guardduty-finding-directory
Regularly-updated directory of all finding types available in Amazon GuardDuty, sourced from AWS documentation

## Automation

This repository includes a GitHub Actions workflow that scrapes the AWS GuardDuty documentation for the list of active finding types. The workflow runs weekly and updates [`findings.json`](findings.json) with the latest information.

If the scraper cannot infer which AWS services a finding relates to, it exits with an error so that the workflow fails and notifies repository owners.

To execute the scraper locally:

```bash
pip install -r requirements.txt
python scrape_guardduty_findings.py
```

The output JSON has the following structure:

```json
{
  "findings": [
    {
      "type": "Finding type string",
      "resource_type": "Resource",
      "source": "Source",
      "severity": "Severity",
      "services": ["example"]
    }
  ]
}
```
