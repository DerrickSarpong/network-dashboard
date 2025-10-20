from scapy.all import sniff, get_if_list

"""
Quick sniff permission test.
Run this from an elevated prompt (Windows: run cmd.exe as Administrator).
"""

def main():
    print("Available interfaces:", get_if_list())
    print("Attempting a short sniff (count=1, timeout=5)...")
    try:
        sniff(count=1, timeout=5)
        print("Sniff succeeded (you have sufficient permissions).")
    except PermissionError as e:
        print("PermissionError:", e)
    except Exception as e:
        print("Other error:", e)


if __name__ == '__main__':
    main()

