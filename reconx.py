#!/usr/bin/env python3

import requests
import whois
import argparse
import socket

def is_ip_address(target):
    """
    Check if the target string is a valid IP address.
    """
    try:
        socket.inet_aton(target)
        return True
    except socket.error:
        return False

def get_ip_info(ip):
    """
    Fetch basic geolocation and network info for the given IP address using ipinfo.io.
    """
    url = f"https://ipinfo.io/{ip}/json"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.json()
        else:
            print("Error fetching IP info: HTTP", response.status_code)
            return None
    except Exception as e:
        print("Error fetching IP info:", e)
        return None

def get_whois_info(domain):
    """
    Retrieve WHOIS information for the given domain.
    """
    try:
        info = whois.whois(domain)
        return info
    except Exception as e:
        print("Error fetching WHOIS info:", e)
        return None

def get_dns_info(domain):
    """
    Resolve the domain to an IP address.
    """
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except Exception as e:
        print("Error performing DNS lookup:", e)
        return None

def main():
    parser = argparse.ArgumentParser(description="Basic OSINT Tool")
    parser.add_argument("target", help="IP address or domain name to investigate")
    args = parser.parse_args()

    target = args.target

    if is_ip_address(target):
        print(f"\nPerforming OSINT on IP address: {target}")
        ip_info = get_ip_info(target)
        if ip_info:
            print("\nIP Information:")
            for key, value in ip_info.items():
                print(f"  {key}: {value}")
    else:
        print(f"\nPerforming OSINT on domain: {target}")
        dns_ip = get_dns_info(target)
        if dns_ip:
            print(f"\nDNS Lookup: {target} resolves to {dns_ip}")
            ip_info = get_ip_info(dns_ip)
            if ip_info:
                print("\nIP Information from resolved IP:")
                for key, value in ip_info.items():
                    print(f"  {key}: {value}")
        whois_info = get_whois_info(target)
        if whois_info:
            print("\nWHOIS Information:")
            # whois_info is typically a dictionary-like object
            for key in whois_info.keys():
                print(f"  {key}: {whois_info[key]}")

if __name__ == "__main__":
    main()
