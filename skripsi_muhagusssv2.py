import subprocess
import argparse

def start_firewall():
    try:
        subprocess.run(['iptables', '-A', 'INPUT', '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '22', '-j', 'REJECT'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-p', 'icmp', '-m', 'icmp', '--icmp-type', '8', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-p', 'icmp', '-m', 'icmp', '--icmp-type', '13', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-p', 'icmp', '-m', 'icmp', '--icmp-type', '14', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--tcp-flags', 'ALL', 'NONE', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-I', 'INPUT', '-p', 'tcp', '--dport', '80', '-m', 'state', '--state', 'NEW', '-m', 'recent', '--set'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-I', 'INPUT', '-p', 'tcp', '--dport', '80', '-m', 'state', '--state', 'NEW', '-m', 'recent', '--update', '--seconds', '20', '--hitcount', '10', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-N', 'BLOCK'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-j', 'LOG', '-I', 'BLOCK', '--log-prefix=”IPTABLES_BLOCK”', '--log-level', '7'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'BLOCK', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '-m', 'tcp', '-m', 'multiport', '!', '--dports', '80,22', '-m', 'recent', '--name', 'PORTSCAN', '--set'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-m', 'recent', '--name', 'PORTSCAN', '--rcheck', '--seconds', '30', '-j', 'BLOCK'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '-m', 'multiport', '!', '--dport', '22,80,443', '-j', 'REJECT', '--reject-with', 'tcp-reset'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '!', '--syn', '-m', 'state', '--state', 'NEW', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--tcp-flags', 'ALL', 'NONE', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--tcp-flags', 'RST', 'RST', '-m', 'limit', '--limit', '2/s', '--limit-burst', '2', '-j', 'ACCEPT'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--tcp-flags', 'RST', 'RST', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '-m', 'state', '--state', 'INVALID', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-N', 'syn_flood'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-p', 'tcp', '--syn', '-j', 'syn_flood'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'syn_flood', '-m', 'limit', '--limit', '2/s', '--limit-burst', '7', '-j', 'RETURN'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'syn_flood', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-s', '0.0.0.0/7', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-s', '2.0.0.0/8', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-s', '5.0.0.0/8', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-s', '7.0.0.0/8', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-s', '10.0.0.0/8', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-s', '23.0.0.0/8', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-s', '27.0.0.0/8', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-s', '31.0.0.0/8', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-s', '36.0.0.0/7', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-s', '39.0.0.0/8', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-s', '42.0.0.0/8', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-s', '49.0.0.0/8', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-s', '50.0.0.0/8', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-s', '77.0.0.0/8', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-s', '78.0.0.0/7', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-s', '92.0.0.0/6', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-s', '96.0.0.0/4', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-s', '112.0.0.0/5', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-s', '120.0.0.0/8', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-s', '169.254.0.0/16', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-s', '172.16.0.0/12', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-s', '173.0.0.0/8', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-s', '174.0.0.0/7', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-s', '176.0.0.0/5', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-s', '184.0.0.0/6', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-s', '192.0.2.0/24', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-s', '197.0.0.0/8', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-s', '198.18.0.0/15', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-s', '223.0.0.0/8', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-s', '224.0.0.0/3', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-t', 'raw', '-D', 'PREROUTING', '-p', 'tcp', '-m', 'tcp', '--syn', '-j', 'CT', '--notrack'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-D', 'INPUT', '-p', 'tcp', '-m', 'tcp', '-m', 'conntrack', '--ctstate', 'INVALID,UNTRACKED', '-j', 'SYNPROXY', '--sack-perm', '--timestamp', '--wscale', '7', '--mss', '1460'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-D', 'INPUT', '-m', 'conntrack', '--ctstate', 'INVALID', '-j', 'DROP'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables-save', '>', '/etc/iptables/rules.v4'], stderr=subprocess.STDOUT, text=True)
        

        print('Firewall telah diaktifkan')
        
    except subprocess.CalledProcessError as e:
        return f"Terjadi kesalahan: {e.output}"

def config_firewall():
    try:
        subprocess.run(['nano', '/etc/knockd.conf'], check=True)
        print("Konfigurasi selesai.")
    except subprocess.CalledProcessError as e:
        return f"Terjadi kesalahan: {e.output}"

def stop_firewall():
    try:
        subprocess.run(['iptables', '-F'], stderr=subprocess.STDOUT, text=True)
        subprocess.run(['iptables', '-X'], stderr=subprocess.STDOUT, text=True)
        print('Firewall telah dinonaktifkan.')
    except subprocess.CalledProcessError as e:
        return f"Terjadi kesalahan: {e.output}"

def main():
    parser = argparse.ArgumentParser(description='Firewall Skripsi Tugas Akhir by Muhammad Agus Saputra.')
    parser.add_argument('-s', '--start', action='store_true', help='Mengaktifkan Firewall.')
    parser.add_argument('-c', '--config', action='store_true', help='Konfigurasi Port Knocking.')
    parser.add_argument('-o', '--stop', action='store_true', help='Menonaktifkan Firewall.')
    
    args = parser.parse_args()
    print('Program ini ialah firewall menggunakan metode Firewall Filtering dan Port Knocking')
    print('Program ini ialah Tugas Skripsi Muhammad Agus Saputra')
    print('Gunakan -h atau memperoleh bantuan penggunaan aplikasi.')
    
    if args.start:
        start_firewall()
    elif args.config:
        config_firewall()
    elif args.stop:
        stop_firewall()
    else:
        print('Parameter tidak tersedia. Gunakan -h atau --help untuk bantuan.')

if __name__ == '__main__':
    main()
