import json
import sys
import requests
from bs4 import BeautifulSoup

URL = "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html"

OUTPUT_FILE = "findings.json"

def determine_services(find_type: str, resource_type: str, source: str) -> list[str]:
    """Infer AWS services from finding fields."""
    text = " ".join([find_type, resource_type, source]).lower()
    services = set()
    if "iam" in text:
        services.add("iam")
    if "s3" in text:
        services.add("s3")
    if "ec2" in text:
        services.add("ec2")
    if "ecs" in text:
        services.add("ec2")
    if "container" in text:
        services.update(["ec2", "ecs", "eks"])
    if "kubernetes" in text:
        services.add("eks")
    if "lambda" in text:
        services.add("lambda")
    if "rds" in text:
        services.add("rds")
    if not services:
        raise ValueError(f"Could not determine services for finding '{find_type}'")
    return sorted(services)

def scrape_findings():
    response = requests.get(URL, timeout=30)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, 'html.parser')

    findings = []

    # Locate table that contains the finding types
    tables = soup.find_all('table')
    target_table = None
    for table in tables:
        headers = [th.get_text(strip=True).lower() for th in table.find_all('th')]
        def has_header(keyword: str) -> bool:
            return any(keyword in h for h in headers)
        if all(has_header(k) for k in ["finding type", "resource type", "foundational data source/feature", "severity"]):

            target_table = table
            break

    if not target_table:
        raise RuntimeError('Could not locate findings table in documentation')

    # Parse rows
    header_cells = [th.get_text(strip=True).lower() for th in target_table.find('tr').find_all('th')]
    def find_idx(keyword: str) -> int:
        for i, text in enumerate(header_cells):
            if keyword in text:
                return i
        raise ValueError(f"Missing expected column '{keyword}'")

    idx_map = {
        'type': find_idx('finding type'),
        'resource_type': find_idx('resource type'),
        'source': find_idx('foundational data source/feature'),
        'severity': find_idx('severity'),

    }

    for row in target_table.find_all('tr')[1:]:
        cells = row.find_all(['td', 'th'])
        if len(cells) < len(idx_map):
            continue
        f_type = cells[idx_map['type']].get_text(strip=True)
        resource_type = cells[idx_map['resource_type']].get_text(strip=True)
        source = cells[idx_map['source']].get_text(strip=True)
        severity = cells[idx_map['severity']].get_text(strip=True).rstrip('+*')
        services = determine_services(f_type, resource_type, source)
        finding = {
            'type': f_type,
            'resource_type': resource_type,
            'source': source,
            'severity': severity,
            'services': services,
        }
        print(finding)
        findings.append(finding)

    exit(0)
    return findings


def main():
    try:
        data = {'findings': scrape_findings()}
    except Exception as exc:  # pragma: no cover - simple error handler
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(data, f, indent=2)

if __name__ == '__main__':
    main()
