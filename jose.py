import nmap
scanner = nmap.PortScanner()
print(scanner.nmap_version())

print("Welcome, this is a simple network scan project by jose bose")
print("""
      ██╗ ██████╗ ███████╗███████╗ ██████╗ ██████╗ ███████╗███████╗
      ██║██╔═══██╗██╔════╝██╔════╝ ██╔══██╗██╔═══██╗██╔════╝██╔═══╝
      ██║██║   ██║███████╗█████╗   ██████╔╝██║   ██║███████╗█████╗ 
 ██   ██║██║   ██║╚════██║██╔══╝   ██╔══██╗██║   ██║╚════██║██╔══╝
 ╚█████╔╝╚██████╔╝███████║███████╗ ██████ ╗╚██████╔╝███████║███████╗
   ╚════╝ ╚═════╝ ╚══════╝╚══════╝  ╚═════╝ ╚═════╝ ╚══════╝╚══════╝
""")
while True:
    what = input("""
       type'man' : manual
       type'scan': scan network
    """)
    try:
        if what == "man":
            print("Hi, this is a project or tool made for begginer friendly network scaning")
        elif what == "scan":
                ip = input("You wnt to enter herev the Ip Address to scan: ")
                print("TheIP you entered :", ip)
                try:
                    print("do you want to scan also for UDP port? type (y/n)")
                    while True:
                        typ =input()
                        if typ == 'y':
                            scan_scan = ' -sU'
                            break
                        elif typ == 'n':
                            scan_scan = ' -sT'
                            print("do want want stealthy scan?(y/n)")
                            while True:
                                stealthy = input()
                                if stealthy == 'y':
                                    scan_scan = ' -sT -sS' 
                                    break
                                elif stealthy == 'n':
                                    break
                                else:
                                    print(" not valid input, please type y or n")
                            break
                        else:
                            print(" not valid input, please type y or n")
                    print("do you want to enable script scan? typwe (y/n)")
                    while True:
                        script = input()
                        if script == 'y':
                            script_scan = True
                            break
                        elif script == 'n':
                            script_scan = False
                            break
                        else:
                            print(" not valid input, please type y or n")
                    print("do want to enable version scan(y/n)")
                    while True:
                        version = input()
                        if version == 'y':
                            version_scan = True
                            break
                        elif version == 'n':
                            version_scan = False
                            break
                        else:
                            print(" not valid input, please type y or n")
                    print("do you want to enable OS detection? type (y/n)")
                    while True:
                        os = input()
                        if os == 'y':
                            os_scan = True
                            break
                        elif os == 'n':
                            os_scan = False
                            break
                        else:
                            print(" not valid input, please type y or n")
                    print("if you want to scan 1 to 1000 ports enter 's' or for full scan enter 'f'")
                    while True:
                        
                        port =input().strip().lower()
                        if port == 's':
                            porter = '1-1000'
                            break
                        elif port == 'f':
                            porter = '1-65535'
                            break
                        else:
                            print("you have entered invalid Characters please enter 's' for scan 1 to 1000 or for full scan enter 'f'")
                except Exception as j:
                    print("An error occurred:", j)
        try:
                arguments = "-T4 -Pn " + scan_scan
                if script_scan:
                 arguments += " -sC"
                if version_scan:
                    arguments += " -sV"
                if os_scan:
                 arguments += " -O"
                scanner.scan(ip, porter, arguments=arguments)
                if ip not in scanner.all_hosts():
                    print(" oops!, Host is not on range or scan has crahesd.")
                else:
                     print("\n yes!, Scan completed successfully.")
                     print(" IP Status:", scanner[ip].state())
                     print(" Protocols Detected:", scanner[ip].all_protocols())

                     for proto in scanner[ip].all_protocols():
                         ports = scanner[ip][proto].keys()
                         print(f"\n"," Protocol: {proto.upper()}")
                         print(f" Open Ports: {list(ports)}")

                         for port in ports:
                             dataofport = scanner[ip][proto][port]
                             stateofport = dataofport.get('state', 'Unknown')
                             servicename = dataofport.get('name', '**')
                             serviceproduct = dataofport.get('product', 'Unknown')
                             serviceversion = dataofport.get('version', '')

                             print(f"   Port {port}:")
                             print(f"      State   : {stateofport}")
                             print(f"      Service : {servicename}")
                             print(f"      Product : {serviceproduct}")
                             print(f"      Version : {serviceversion}")
                         if script_scan:
                             if 'script' in dataofport:
                                 print("      Script Results:")
                                 for script_name, script_output in dataofport["script"].items():
                                     if "ERROR" in script_output.upper():
                                         print(f"     {script_name}: Script execution has failed")
                                     else:
                                         print(f"     {script_name}: {script_output}")
                         if os_scan:
                              if 'osmatch' in scanner[ip]:
                                   print("\n","OS Detection Results:")
                                   for match in scanner[ip]['osmatch']:
                                        print(f"  - {match['name']}",end="")
                                        print(f"Accuracy :{match['accuracy']}%")

                              else:
                                   print("\n","OS Detection have No match found.")
        except:
            print("An error occurred during scanning process ")
    except:
         print("An error occurred:")