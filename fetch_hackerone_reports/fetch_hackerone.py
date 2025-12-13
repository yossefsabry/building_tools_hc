#!/usr/bin/env python3
"""
Fetch public disclosed HackerOne reports using the PUBLIC GraphQL endpoint.
NO authentication required.
"""

import requests
import json
import sys
import argparse
import base64

def decode_id(gid):
    """Decode Global ID to get the numeric report ID"""
    try:
        # gid is like "gid://hackerone/Report/12345"
        # base64 decode it
        decoded = base64.b64decode(gid).decode('utf-8')
        return decoded.split('/')[-1]
    except:
        return gid

def fetch_public_reports(limit=10):
    """
    Fetch public disclosed reports using HackerOne's public GraphQL endpoint.
    
    Args:
        limit: Number of reports to return
    """
    
    url = "https://hackerone.com/graphql"
    
    # Query to fetch public disclosed reports
    query = """
    query PublicReports($count: Int, $where: FiltersReportFilterInput) {
      reports(first: $count, where: $where) {
        edges {
          node {
            id
            title
            disclosed_at
            created_at
            severity {
              rating
              score
            }
            team {
              handle
              name
              currency
            }
            bounties {
              total_count
            }
            votes {
              total_count
            }
          }
        }
      }
    }
    """
    
    # Base filter: disclosed reports only
    where_filter = {
        "disclosed_at": { "_is_null": False }
    }
    
    variables = {
        "count": limit,
        "where": where_filter
    }
    
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "*/*",
    }
    
    try:
        response = requests.post(
            url,
            json={"query": query, "variables": variables},
            headers=headers,
            timeout=30
        )
        
        if response.status_code != 200:
            return {
                "success": False,
                "error": f"HTTP {response.status_code}",
                "details": response.text[:200]
            }
        
        data = response.json()
        
        if 'errors' in data:
            return {
                "success": False,
                "error": "GraphQL errors",
                "details": data['errors']
            }
        
        # Extract reports
        edges = data.get('data', {}).get('reports', {}).get('edges', [])
        
        reports = []
        for edge in edges:
            node = edge.get('node', {})
            report_id = decode_id(node.get('id'))
            
            reports.append({
                'id': int(report_id) if report_id.isdigit() else report_id,
                'title': node.get('title'),
                'severity_rating': node.get('severity', {}).get('rating') if node.get('severity') else None,
                'severity_score': node.get('severity', {}).get('score') if node.get('severity') else None,
                'bounty_amount': None, # Public API doesn't easily expose amount without auth
                'currency': node.get('team', {}).get('currency', 'USD'),
                'disclosed_at': node.get('disclosed_at'),
                'created_at': node.get('created_at'),
                'program_handle': node.get('team', {}).get('handle'),
                'program_name': node.get('team', {}).get('name'),
                'votes': node.get('votes', {}).get('total_count', 0),
                'url': f"https://hackerone.com/reports/{report_id}"
            })
        
        return {
            "success": True,
            "source": "HackerOne Public GraphQL",
            "total_fetched": len(reports),
            "reports": reports
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": "Unexpected error",
            "details": str(e)
        }

def search_report(report_id):
    """
    Search for a specific report by ID using public GraphQL endpoint.
    """
    url = "https://hackerone.com/graphql"
    
    query = """
    query Report($id: Int!) {
      report(id: $id) {
        id
        title
        disclosed_at
        created_at
        vulnerability_information
        severity {
          rating
          score
        }
        team {
          handle
          name
          currency
        }
        bounties {
          total_count
        }
        votes {
          total_count
        }
      }
    }
    """
    
    variables = {
        "id": int(report_id)
    }
    
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "*/*",
    }
    
    try:
        response = requests.post(
            url,
            json={"query": query, "variables": variables},
            headers=headers,
            timeout=30
        )
        
        if response.status_code != 200:
            return {
                "success": False,
                "error": f"HTTP {response.status_code}",
                "details": response.text[:200]
            }
        
        data = response.json()
        
        if 'errors' in data:
            return {
                "success": False,
                "error": "GraphQL errors",
                "details": data['errors']
            }
            
        report = data.get('data', {}).get('report')
        
        if not report:
             return {
                "success": False,
                "error": "Report not found or private"
            }
            
        return {
            "success": True,
            "report": {
                'id': report.get('id'),
                'title': report.get('title'),
                'severity_rating': report.get('severity', {}).get('rating') if report.get('severity') else None,
                'severity_score': report.get('severity', {}).get('score') if report.get('severity') else None,
                'vulnerability_information': report.get('vulnerability_information'),
                'bounty_amount': None,
                'currency': report.get('team', {}).get('currency', 'USD'),
                'disclosed_at': report.get('disclosed_at'),
                'created_at': report.get('created_at'),
                'program_handle': report.get('team', {}).get('handle'),
                'program_name': report.get('team', {}).get('name'),
                'votes': report.get('votes', {}).get('total_count', 0),
                'url': f"https://hackerone.com/reports/{report.get('id')}"
            }
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": "Unexpected error",
            "details": str(e)
        }

def main():
    parser = argparse.ArgumentParser(description='Fetch HackerOne public disclosed reports')
    parser.add_argument('-n', '--number', type=int, default=10,
                        help='Number of reports to fetch (default: 10)')
    parser.add_argument('-s', '--search', type=str,
                        help='Search for specific report by ID')
    
    args = parser.parse_args()
    
    if args.search:
        result = search_report(args.search)
    else:
        result = fetch_public_reports(args.number)
    
    print(json.dumps(result, indent=2))
    
    sys.exit(0 if result.get('success') else 1)

if __name__ == "__main__":
    main()
