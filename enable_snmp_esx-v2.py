# pip install pyvmomi paramiko requests
# snmpwalk -r:192.168.118.31 -c:"public"
# esx.txt file include list of esx hosts "edit befor run it"

import csv
import time
import paramiko
import ssl
import atexit
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim

# Disable SSL warnings globally
ssl._create_default_https_context = ssl._create_unverified_context

def disable_ssl_verification():
    """Create SSL context with hostname check disabled (Python 3.10+)"""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context

def connect_to_host(ip, username, password):
    """Connect directly to ESXi host using pyVmomi"""
    try:
        print(f"Connecting to ESXi host {ip}...")
        si = SmartConnect(
            host=ip,
            user=username,
            pwd=password,
            port=443,
            sslContext=disable_ssl_verification()
        )
        atexit.register(Disconnect, si)
        print(f"Successfully connected to {ip}")
        return si.RetrieveContent()
    except Exception as e:
        print(f"Failed to connect to {ip}: {e}")
        return None

def get_host_system(content, target_ip):
    """Find HostSystem by matching management IP (vmk0 or vmk with IP)"""
    try:
        container = content.viewManager.CreateContainerView(
            content.rootFolder, [vim.HostSystem], True
        )
        for host in container.view:
            # Method 1: Check host.name (often the IP in standalone)
            if host.name == target_ip:
                print(f"  Found host by name: {host.name}")
                container.Destroy()
                return host

            # Method 2: Check VMkernel interfaces (vmk0, vmk1, etc.)
            try:
                net_config = host.config.network
                if net_config and net_config.vswitch:
                    for vswitch in net_config.vswitch:
                        if vswitch.portgroup:
                            for pg in vswitch.portgroup:
                                if hasattr(pg, 'spec') and hasattr(pg.spec, 'ipSettings') and pg.spec.ipSettings.ipAddress == target_ip:
                                    print(f"  Found host via portgroup IP: {pg.spec.ipSettings.ipAddress}")
                                    container.Destroy()
                                    return host
            except:
                pass

            # Method 3: Check VMkernel adapters directly
            try:
                vmk_list = host.configManager.networkSystem.networkInfo.vnic
                for vmk in vmk_list:
                    if vmk.spec.ip.ipAddress == target_ip:
                        print(f"  Found host via VMK IP: {vmk.spec.ip.ipAddress}")
                        container.Destroy()
                        return host
            except:
                pass

            # Method 4: Fallback - check summary.managementServerIp (rarely used)
            if hasattr(host.summary, 'managementServerIp') and host.summary.managementServerIp == target_ip:
                print(f"  Found host via managementServerIp")
                container.Destroy()
                return host

        container.Destroy()
        return None
    except Exception as e:
        print(f"  Error searching for host: {e}")
        return None

def toggle_ssh_service(host, enable=True):
    """Enable or disable SSH service"""
    try:
        service_manager = host.configManager.serviceSystem
        ssh_service = None
        for svc in service_manager.serviceInfo.service:
            if svc.key == "TSM-SSH":
                ssh_service = svc
                break

        if not ssh_service:
            print("  Error: SSH service (TSM-SSH) not found")
            return False

        if enable and not ssh_service.running:
            print("  Enabling SSH...")
            service_manager.Start(ssh_service.key)
            time.sleep(6)
            print("  SSH enabled")
        elif not enable and ssh_service.running:
            print("  Disabling SSH...")
            service_manager.Stop(ssh_service.key)
            time.sleep(2)
            print("  SSH disabled")
        else:
            state = "enabled" if ssh_service.running else "disabled"
            print(f"  SSH already {state}")

        return True
    except Exception as e:
        print(f"  Error managing SSH service: {e}")
        return False

def execute_ssh_commands(ip, username, password, commands):
    """Execute SSH commands"""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        print(f"  Connecting via SSH to {ip}...")
        ssh.connect(ip, username=username, password=password, timeout=15,
                    allow_agent=False, look_for_keys=False)
        print(f"  SSH connected to {ip}")

        for cmd in commands:
            print(f"    Running: {cmd}")
            stdin, stdout, stderr = ssh.exec_command(cmd)
            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()

            if output:
                print(f"    Output: {output}")
            if error:
                print(f"    Error: {error}")

        ssh.close()
        return True
    except Exception as e:
        print(f"  SSH failed to {ip}: {e}")
        return False
    finally:
        try:
            ssh.close()
        except:
            pass

def enable_snmp_v2c(ip, username, password, community="public"):
    """Enable SNMPv2c with community string"""
    print(f"  Configuring SNMPv2c with community: {community}")

    commands = [
        "esxcli system snmp set --enable false",
        f"esxcli system snmp set --communities {community}",
        "esxcli system snmp set --enable true",
        "esxcli network firewall ruleset set --ruleset-id=snmp --enabled=true",
        "esxcli network firewall ruleset set --ruleset-id=snmp --allowed-all=true"
    ]

    return execute_ssh_commands(ip, username, password, commands)

def main():
    print("Starting Direct ESXi SNMPv2c Enablement Script (community: public)\n")

    hosts_list = []
    try:
        with open('esx.txt', 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            for row in reader:
                row = [item.strip() for item in row]
                if len(row) >= 3 and row[0]:
                    hosts_list.append({
                        'ip': row[0],
                        'username': row[1],
                        'password': row[2]
                    })
        print(f"Loaded {len(hosts_list)} hosts from esx.txt\n")
    except FileNotFoundError:
        print("Error: esx.txt not found!")
        return
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    success_count = 0
    for host in hosts_list:
        ip = host['ip']
        print(f"{'='*60}")
        print(f"Processing host: {ip}")
        print(f"{'='*60}")

        # Step 1: Connect via pyVmomi
        content = connect_to_host(ip, host['username'], host['password'])
        if not content:
            print(f"Skipping {ip} due to connection failure\n")
            continue

        # Step 2: Find HostSystem by IP
        esxi_host = get_host_system(content, ip)
        if not esxi_host:
            print(f"  Could not find HostSystem for IP {ip}")
            print(f"  Tip: Use the **management IP** (vmk0) shown in ESXi DCUI or Web UI\n")
            continue

        # Step 3: Enable SSH
        if not toggle_ssh_service(esxi_host, enable=True):
            print(f"  Failed to enable SSH on {ip}\n")
            continue

        time.sleep(12)

        # Step 4: Enable SNMPv2c
        snmp_success = enable_snmp_v2c(ip, host['username'], host['password'], "public")

        if snmp_success:
            print(f"  SNMPv2c successfully enabled on {ip} with community 'public'")
            success_count += 1
        else:
            print(f"  Failed to enable SNMPv2c on {ip}")

        # Step 5: Disable SSH
        time.sleep(3)
        toggle_ssh_service(esxi_host, enable=False)

        print(f"Finished processing {ip}\n")

    print(f"{'='*60}")
    print(f"SUMMARY: {success_count}/{len(hosts_list)} hosts configured with SNMPv2c")
    print(f"Community string: public")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
