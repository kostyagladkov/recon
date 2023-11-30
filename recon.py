import asyncio
import aiodns
import sys
import re
import os

class Recon:
    def __init__(self):
        self.url = sys.argv[1]

    async def run_command(self, command):
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        return {'stdout': stdout.decode(), 'stderr': stderr.decode(), 'returncode': process.returncode}

    async def install_scanners(self):
        package_managers = {
            "aptx": [
                "sudo apt install dnsrecon subfinder assetfinder python3",
                "python3 -m pip install --user pipx",
                "pipx install bbot"
            ],
            "pacmanx": [
                "sudo pacman -S dnsrecon subfinder assetfinder python3",
                "python3 -m pip install --user pipx",
                "pipx install bbot"
            ]
        }

        for manager, commands in package_managers.items():
            if which(manager):
                for command in commands:
                    result = await self.run_command(command)
                    if result['returncode'] != 0:
                        print(f"Command '{command}' failed with return code {result['returncode']} and stderr:\n{result['stderr']}")
                        sys.exit()
                break  
        else:
            sys.stderr.write("\nCan't find the packet manager (apt/pacman)...\nPlease install the programs manually before running the program using your packet manager\n")
            sys.exit()

    async def check_scanners(self):
        sys.stderr.write("Checking scanners...\n")
        scanner_binaries = ["bbot", "subfinder", "dnsrecon", "assetfinder"]

        missing_binaries = []

        for file in scanner_binaries:
            if which(file) is None:
                missing_binaries.append(file)

        if missing_binaries:
            sys.stderr.write("\nThe following binary files are missing or not executable:\n")
            for file in missing_binaries:
                sys.stderr.write(f"*{file}\n")
            sys.stderr.write("\nWould you like to install them? Y/N\n")
            response = input()

            if response.lower() == "yes" or response.lower() == "y":
                await self.install_scanners()

            else:
                sys.stderr.write("\nMake sure to install the programs manually before running the program!\n")
                sys.exit()
            
        else:
            sys.stderr.write("\nAll required scanners are in place\n\n")

    async def check_ips(self, domains):
        ip_addresses = []
        resolver = aiodns.DNSResolver()

        async def resolve_domain(domain):
            try:
                result = await resolver.query(domain, 'A')  # Specify 'A' for IPv4 resolution, use 'AAAA' for IPv6
                ip_addresses.append((domain, result[0].host))
            except aiodns.error.DNSError:
                ip_addresses.append((domain, "Not Found IP"))

        await asyncio.gather(*[resolve_domain(domain) for domain in domains])
        return ip_addresses


    async def process_ip_addresses(self, ip_list):
        ip_addresses = []

        async def process_domain(domain, ip):
            if ip != "Not Found IP":
                command = f"sudo masscan {ip} -p80,443"
                result = await self.run_command(command)
                if "stdout" in result:
                    open_ports = re.findall(r'(\d+\/\w+)', result["stdout"])
                    formatted_ports = ' '.join(open_ports) if open_ports else "Ports not found"
                    ip_addresses.append((domain, formatted_ports))
                else:
                    ip_addresses.append((domain, "Not Found"))
            else:
                ip_addresses.append((domain, "Not Found IP"))

        await asyncio.gather(*[process_domain(domain, ip) for domain, ip in ip_list])
        return ip_addresses


    async def bbot(self):
        output = await self.run_command(f"bbot -t {self.url} -f subdomain-enum -y -s")
        domain_pattern = r"\[DNS_NAME\]\s+(\S+)"
        domain_names = re.findall(domain_pattern, output['stdout'])
        sys.stderr.write(f"* Done bbot --- result has {len(domain_names)} domains\n")
        return domain_names

    async def subfinder(self):
        output = await self.run_command(f"subfinder -d {self.url}")
        domain_names = output['stdout'].strip().split("\n")
        sys.stderr.write(f"* Done subfinder --- result has {len(domain_names)} domains\n")
        return domain_names

    async def dnsrecon(self):
        output = await self.run_command(f"dnsrecon -d {self.url} -D /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -t brt")
        domain_pattern = r'A\s+(\S+)'
        domain_names = re.findall(domain_pattern, output['stdout'])
        sys.stderr.write(f"* Done dnsrecon --- result has {len(domain_names)} domains\n")
        return domain_names

    async def assetfinder(self):
        output = await self.run_command(f"assetfinder {self.url} -subs-only")
        domain_names = output['stdout'].strip().split("\n")
        sys.stderr.write(f"* Done assetfinder --- result has {len(domain_names)} domains\n")
        return domain_names

def printer(list):
    port_list_str = '\n'.join([f">{item[0]} --- {item[1]}" for item in list]) + '\n'
    return port_list_str

def which(cmd):

    if os.path.dirname(cmd):
        if os.access(cmd, os.X_OK):
            return cmd
        return None

    path = os.environ.get("PATH", os.defpath).split(os.pathsep)

    for dir in path:
        executable = os.path.join(dir, cmd)
        if os.access(executable, os.X_OK):
            return executable

    return None

async def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Improper usage..\n\nUsage: python recon.py url")
        return

    recon_instance = Recon()
    await recon_instance.check_scanners()

    results = await asyncio.gather(
        recon_instance.bbot(),
        recon_instance.subfinder(),
        recon_instance.dnsrecon(),
        recon_instance.assetfinder()
    )

    all_subs = [item for sublist in results for item in sublist]
    unique_subs = list(set(all_subs))
    
    sys.stderr.write(f"\n\nYour unique subdomains are:\n")
    for item in unique_subs:
        print(f"> {item}")

    
    output_ips = await recon_instance.check_ips(unique_subs)

    sys.stderr.write(f"\n\nThe IPs for those subdomains are:\n")
    print(printer(output_ips))

    # TODO Check if masscan is installed
    output_ports = await recon_instance.process_ip_addresses(output_ips)

    sys.stderr.write(f"\n\nThe ports for those subdomains are:\n")
    print(printer(output_ports))

if __name__ == "__main__":
    asyncio.run(main())

# TODO add nmap and file saving