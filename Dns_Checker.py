#!/usr/bin/env python3
"""
DNS Record Checker for Email Security
"""

import dns.resolver

def check_spf(domain):
    """Check SPF record for domain"""
    try:
        result = dns.resolver.resolve(domain, 'TXT')
        for record in result:
            if 'v=spf1' in str(record):
                return str(record)
        return "No SPF record found"
    except Exception as e:
        return f"Error checking SPF: {str(e)}"

def check_dmarc(domain):
    """Check DMARC record"""
    try:
        dmarc_domain = f"_dmarc.{domain}"
        result = dns.resolver.resolve(dmarc_domain, 'TXT')
        for record in result:
            if 'v=DMARC1' in str(record):
                return str(record)
        return "No DMARC record found"
    except Exception as e:
        return f"Error checking DMARC: {str(e)}"

# Usage example (uncomment to run):
domain = "greenstone.com.au"
print("Domain:", domain)
print("SPF Record:", check_spf(domain))
print("DMARC Record:", check_dmarc(domain))
