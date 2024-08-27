import os
import socket
import requests
import whois
import logging
import subprocess
import time
import nmap  # Import python-nmap
from tqdm import tqdm
from colorama import Fore, Style, init
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Initialize colorama
init(autoreset=True)

# Setup logging
logging.basicConfig(filename='bytebuster.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Load environment variables
WPSCAN_API_KEY = os.getenv('WPSCAN_API_KEY')

# Global variable to store the target URL
target_url = None

def clear_screen():
    """Clear the console screen."""
    os.system('clear' if os.name == 'posix' else 'cls')

def print_header():
    """Print the header to be used as a sticky part of the console."""
    header = Fore.GREEN + """
██████████████████████████████████████████████████████████████████████████████████████████████████
████  ██████  ████  ██████   ████  ████  ██████  ██████  ████  ████  ██████  ████  ██████  ██████  ████
████  ██    ██  ██    ██      ██    ██    ██    ██    ██  ██  ██    ██  ██    ██    ██    ██    ██  ██
████  ██████    ██    ██████  ██    ██    ██████    ██████  ██  ██    ██████  ██    ██████  ██    ██████
████  ██    ██  ██    ██      ██    ██    ██    ██    ██  ██  ██    ██      ██    ██    ██    ██      ██
████  ██████    ██    ██████  ██████████  ██████  ██████  ██  ██    ██████  ██████████  ██    ██████████                         ██████████████████████████████████████████████████████████████████████████████████ ©Jessekimani

"""
    print(header)

def type_text(text, delay=0.0001):
    """Print text character by character with animation effect."""
    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay)
    print()  # Newline after text

def warning_animation():
    """Display a warning animation for invalid consent responses."""
    for _ in range(3):
        print(Fore.RED + "Invalid response. You must agree to the terms to use this application.")
        time.sleep(1)
        clear_screen()
        print_header()
        time.sleep(0.5)

def get_consent():
    """Display the consent prompt and handle user agreement."""
    consent_text = """
                            ****************************************
                            *      USER AGREEMENT AND CONSENT      *
                            ****************************************
                            * This application is intended for use *
                            * in network and security scanning.    *
                            * It is your responsibility to ensure  *
                            * that you have permission to scan the *
                            * target systems. Unauthorized scanning*
                            * may be illegal and could lead to     *
                            * legal consequences. By using this    *
                            * application, you agree to use it     *
                            * responsibly and ethically.           *
                            *                                      *
                            * For more information, visit our      *
                            * website or contact support.          *
                            ****************************************
                                 Networksandcircuits.co.ke 
    """
    print(consent_text)
    
    while True:
        print(Fore.YELLOW + "Do you agree to the terms and conditions? (yes/no): ", end='')
        consent = input().strip().lower()
        if consent == "yes":
            print(Fore.GREEN + "Thank you for agreeing to the terms. You may now proceed.")
            break
        elif consent == "no":
            warning_animation()
        else:
            warning_animation()

def ensure_url_scheme(url):
    """Ensure the URL has a scheme (https:// or http://), prefer https://."""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    if not is_url_reachable(url):
        url = url.replace('https://', 'http://')
    
    return url

def is_url_reachable(url):
    """Check if a URL is reachable."""
    try:
        response = requests.head(url, timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False

def get_target_url():
    """Prompt the user to set the target URL."""
    global target_url
    while True:
        print(Fore.YELLOW + "Enter the target URL (e.g., example.com): ", end='')
        target_url = input().strip()
        if target_url:
            target_url = ensure_url_scheme(target_url)
            print(Fore.GREEN + f"Target URL set to {target_url}")
            break
        else:
            print(Fore.RED + "Invalid URL. Please enter a valid URL.")

def print_loading_animation():
    """Display a loading animation."""
    animation = ['|', '/', '-', '\\']
    for _ in range(20):  # Repeat the animation for a short duration
        for symbol in animation:
            print(f'\rLoading {symbol}', end='', flush=True)
            time.sleep(0.1)
    print()  # Newline after animation

def print_progress(description):
    """Print a progress bar with dynamic effects."""
    for _ in tqdm(range(100), desc=description, bar_format="{l_bar}{bar} [ {n_fmt}/{total_fmt} ]", ascii=True):
        time.sleep(0.05)  # Simulate work being done

def get_ip_information(url):
    """Retrieve IP-related details of the target."""
    try:
        # Ensure the URL does not have scheme
        if url.startswith('http://'):
            url = url.split('//')[1]
        elif url.startswith('https://'):
            url = url.split('//')[1]

        ip = socket.gethostbyname(url)
        print(Fore.GREEN + f"IP Address for {url}: {ip}")
        return ip
    except socket.gaierror as e:
        print(Fore.RED + f"Error: Unable to retrieve IP address. {e}")
        return None

def perform_network_scan(target_ip):
    """Perform a network scan using nmap."""
    try:
        nm = nmap.PortScanner()
        print(Fore.YELLOW + f"Performing network scan on {target_ip}...")
        nm.scan(hosts=target_ip, arguments='-T4 -A -v')
        
        # Print scan results
        print(Fore.GREEN + f"\nScan Results for {target_ip}:\n")
        scan_output = nm.csv()
        print(Fore.CYAN + f"{scan_output}\n")
        
        # Detailed scan information
        for host in nm.all_hosts():
            print(Fore.MAGENTA + f"Host: {host}")
            print(Fore.YELLOW + f"State: {nm[host].state()}")
            for proto in nm[host].all_protocols():
                print(Fore.GREEN + f"Protocol: {proto}")
                ports = nm[host][proto].keys()
                for port in ports:
                    port_info = f"Port: {port}, State: {nm[host][proto][port]['state']}"
                    print(Fore.RED + port_info)
                    
    except Exception as e:
        print(Fore.RED + f"Error during scan: {str(e)}")
        logging.error(f"Error during scan: {str(e)}")

def run_wpscan(url):
    """Run WPScan on the target URL."""
    try:
        if not WPSCAN_API_KEY:
            print(Fore.RED + "WPScan API key not found in .env file.")
            return
        
        print(Fore.YELLOW + f"Running WPScan on {url}...")
        wpscan_cmd = f"wpscan --url {url} --api-token {WPSCAN_API_KEY} --random-user-agent --no-banner"
        result = subprocess.run(wpscan_cmd, shell=True, capture_output=True, text=True)
        print(Fore.GREEN + result.stdout)
        
    except Exception as e:
        print(Fore.RED + f"Error running WPScan: {str(e)}")
        logging.error(f"Error running WPScan: {str(e)}")

def run_whois(url):
    """Run WHOIS query on the target URL."""
    try:
        print(Fore.YELLOW + f"Running WHOIS query on {url}...")
        whois_result = whois.whois(url)
        print(Fore.GREEN + f"WHOIS Result for {url}:")
        for key, value in whois_result.items():
            print(Fore.CYAN + f"{key}: {value}")
        
    except Exception as e:
        print(Fore.RED + f"Error during WHOIS query: {str(e)}")
        logging.error(f"Error during WHOIS query: {str(e)}")

def run_ip_information_scan():
    """Run IP information scan."""
    if target_url:
        ip = get_ip_information(target_url)
        if ip:
            perform_network_scan(ip)
    else:
        print(Fore.RED + "Target URL is not set. Please set the target URL first.")

def run_wp_scan():
    """Run WPScan on the target URL."""
    if target_url:
        run_wpscan(target_url)
    else:
        print(Fore.RED + "Target URL is not set. Please set the target URL first.")

def run_whois_query():
    """Run WHOIS query on the target URL."""
    if target_url:
        run_whois(target_url)
    else:
        print(Fore.RED + "Target URL is not set. Please set the target URL first.")

def main():
    """Main function to run the application."""
    clear_screen()
    print_header()
    
    get_consent()

    while True:
        print(Fore.BLUE + """
        1. Set Target URL
        2. Run IP Information Scan
        3. Run WPScan
        4. Run WHOIS Query
        5. Exit
        """)
        choice = input(Fore.YELLOW + "Enter your choice (1-5): ").strip()

        if choice == '1':
            get_target_url()
        elif choice == '2':
            print_loading_animation()
            run_ip_information_scan()
        elif choice == '3':
            print_loading_animation()
            run_wp_scan()
        elif choice == '4':
            print_loading_animation()
            run_whois_query()
        elif choice == '5':
            print(Fore.GREEN + "Exiting...")
            break
        else:
            print(Fore.RED + "Invalid choice. Please enter a number between 1 and 5.")

if __name__ == "__main__":
    main()

