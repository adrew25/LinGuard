from scans import network_scan

if __name__ == "__main__":
    results = network_scan.scan()
    if results:
        print("Unexpected network connections found:")
        for conn in results:
            print(conn)
    else:
        print("No unexpected network activity detected.")
