
##
## This is a list of software that needs to be installed to use this program:
## POC SEEKER    https://github.com/0xyassine/poc-seeker/blob/master/README.md
## FFUF: https://github.com/ffuf/ffuf
## Nuclei templates for WordPress (nuclei-wordfence-cve): https://github.com/topscoder/nuclei-wordfence-cve
## Nikto: https://github.com/sullo/nikto
## Wp-scan: https://github.com/wpscanteam/wpscan
## OpenSSL: https://openssl.org/source/old/0.9.x/
## python: https://www.python.org/downloads/


import subprocess
import os

print("This script is a menu system to generate reports for some first steps in pentesting")
print("Please pay attention to the Software install requriements.md document. ")
print("The software listed in the document needs to be installed in order for the script to run properly .")
print("")
print("DNS: querys dns info")
print("")
print("Discover: looks for subdomains and crawls sites")
print("")
print("Attack: CVEs- looks for pocs and exploits, Wordpress- looks for vulns, Test TLS- tests connections using tls1.0")
print("")
print("Other stuff: uncover- finds hosts on internet, fuff- web fuzzer, more options later")
print("")
print("Report Generation: combines all the generated reports into one final report")

def recon():
    print("DNS Check")
    print("This will generate the report recon_results.txt, to be generated")
    # Ask for domain name or IP address
    target = input("Enter the domain name or IP address: ")
    
    # Run nslookup command
    result = subprocess.run(['nslookup', target], capture_output=True, text=True)
    with open('recon_results.txt', 'a') as file:
        file.write(result.stdout)
        
    # Run dig command 
    result2 = subprocess.run(['dig', target], capture_output=True, text=True )
    with open('recon_results.txt', 'a') as file:
        file.write(result2.stdout)
    
        # Run sslscan 
    result3 = subprocess.run(['sslscan', target], capture_output=True, text=True )
    with open('recon_results.txt', 'a') as file:
        file.write(result3.stdout)
        with open('recon_results.txt', 'r') as file:
            content = file.read()
            print("\nFile Content:\n")
            print(content)    


def discover():
    # Print "Discover" to the screen
    print("Discover")
    print("This will generate the reports discover_subdomains.txt to be generated")
    target = input("Enter the domain name or IP address: ")
    command_subf = f"subfinder -d {target}"

    result = subprocess.run(command_subf, shell=True, check=True, capture_output=True, text=True)
    with open('discover_subdomains.txt', 'a') as file:
        file.write(result.stdout)
        with open('discover_subdomains.txt', 'r') as file:
            content = file.read()
            print("\nFile Content:\n")
            print(content)
    
    # running pd's katana against subdomains
    #command_kat = f"katana -list discover_subdomains.txt -c 10 -rlm 100"
    #result2 = subprocess.run(command_kat, shell=True, check=True, capture_output=True, text=True)
    #with open('discover_katana.txt', 'a') as file:
    #    file.write(result2.stdout)
    

def submenu():
    while True:
        print("\nSubmenu:")
        print("1. uncover")
        print("2. ffuf")
        print("3. Exit to previous menu")

        choice = input("Enter your choice: ")
    
        if choice == '1':
            print("You selected Submenu Option 1. uncover")
            print("This will generate the report uncover_findings.txt, to be generated")
            target = input("Enter the domain name or IP address: ")
            command_uncover = f"uncover -q {target} -e shodan,hunter,netlas,criminalip,hunterhow"
            result_uncover = subprocess.run(command_uncover, shell=True, check=True, capture_output=True, text=True)
            with open('uncover_findings.txt', 'a') as file:
                file.write(result_uncover.stdout)

        elif choice == '2':
            print("You selected Submenu Option 2.")
            print("This will generate the report ffuf_findings.txt, to be generated")
            target = input("Enter the domain name (with http:// or https://) or IP address: ")
            command_ffuf = f'ffuf -u "{target}/FUZZ" -w "/usr/share/wordlists/wfuzz/general/admin-panels.txt"'


            result_ffuf = subprocess.run(command_ffuf, shell=True, check=True, capture_output=True, text=True)
            with open('ffuf_findings.txt', 'a') as file:
                file.write(result_ffuf.stdout)
                #with open('ffuf_findings.txt', 'a') as file:
                #    file.write(result_ffuf.stdout)
    
        elif choice == '3':
            print("Returning to Main Menu.")
            break



        else:
            print("Invalid choice. Please try again.")

def attacksubmenu():
    # Print "Attack" to the screen
    # CVE's create report
            while True:
                print("\nattacksubmenu:")
                print("1. CVE's")
                print("2. WordPress")
                print("3. Test TLS")
                print("4. exit to main menu")

                choice = input("Enter your choice: ")
            
                if choice == '1':
                    print("1. CVE Search.")
                    print("This will generate the reports cvemap_findings.txt, poc_findings.txt, and searchsploit_findings.txt to be generated")
                    CVEID = input("Enter the CVE number: EX. CVE-2014-0160, this may take a little while: ")
                    #pdtools cvemap search
                    command_cvemap = f"cvemap -id {CVEID} -json"
                    result_cvemap = subprocess.run(command_cvemap, shell=True, check=True, capture_output=True, text=True)
                    with open('cvemap_findings.txt', 'w') as file:
                        file.write(result_cvemap.stdout)
                    
                    #poc-seeker lookup
                    command_pocseeker = f"poc-seeker -c -q {CVEID} -s github,sploitus,exploit-db,vulnerability-lab"

                    #begintest
                    result_poc = subprocess.run(command_pocseeker, shell=True, check=True, capture_output=True, text=True)
                    with open('poc_findings.txt', 'w') as file:
                        file.write(result_poc.stdout)
                    
                    #searchsploit
                    command_searchsploit= f"searchsploit --cve {CVEID}"
                    result_searchsploit = subprocess.run(command_searchsploit, shell=True, check=True, capture_output=True, text=True)
                    with open('searchsploit_findings.txt', 'w') as file:
                        file.write(result_searchsploit.stdout)
                
                elif choice == '2':
                    print("2. Wordpress")
                    print("This will generate the report wpnuclei_findings.txt, to be generated")
                    WP_site = input("Enter the URL for the wordpress site (this will take a while): ")
                    command_wpnuclei = f"nuclei -u {WP_site} -t github/topscoder/nuclei-wordfence-cve"
                    result_wpnuclei = subprocess.run(command_wpnuclei, shell=True, check=True, capture_output=True, text=True)
                    with open('wpnuclei_findings.txt', 'w') as file:
                        file.write(result_wpnuclei.stdout)
                
                elif choice == '3':
                    print("3. TLS Connection Test")
                    print("This will generate the report tlsconnect_findings.txt, to be generated")
                    TLS_site = input("Enter the domain to test TLS connection ): ")
                    command_tlsconnect = f"openssl s_client -connect {TLS_site}:443 -tls1"
                    result_tlsconnect = subprocess.run(command_tlsconnect, shell=True, check=True, capture_output=True, text=True)
                    with open('tlsconnect_findings.txt', 'w') as file:
                        file.write(result_tlsconnect.stdout)
                    
                elif choice == '4':
                    print("Returning to Main Menu.")
                    break
                
                else:
                    print("Invalid choice. Please try again.")



def reportgen():
    print("Report Generation")

##################################
# Ask the user for the name of the output file
    output_file = input("Enter the name for the combined output file (with .txt extension): ")

# Ask the user for the directory containing the .txt files
    directory = input("Enter the directory path containing the .txt files: ")

# Get a list of all .txt files in the specified directory
    txt_files = [f for f in os.listdir(directory) if f.endswith('.txt')]

# Open the output file in write mode
    with open(output_file, 'w') as outfile:
    # Iterate over each .txt file
        for filename in txt_files:
            file_path = os.path.join(directory, filename)
        # Check if the file exists
            if os.path.isfile(file_path):
                with open(file_path, 'r') as infile:
                # Read the content of the file and write it to the output file
                    outfile.write(infile.read())
                    outfile.write("\n")  # Optional: Add a newline between files
            else:
                print(f"File {filename} not found!")

            print(f"All .txt files in {directory} have been combined into {output_file}")



def cleanup():

    try:
        # Get the current working directory
        current_directory = os.getcwd()
        
        # Find all .txt files in the current directory
        txt_files = [f for f in os.listdir(current_directory) if f.endswith(".txt") and os.path.isfile(f)]
        
        # If there are no .txt files, exit the function
        if not txt_files:
            print("No .txt files found in the current directory.")
            return
        
        # Display warning and ask for confirmation
        print("The following .txt files will be deleted:")
        for file in txt_files:
            print(file)
        
        confirm = input("Are you sure you want to delete these files? (yes/no): ").lower()
        
        if confirm == "yes":
            for filename in txt_files:
                file_path = os.path.join(current_directory, filename)
                os.remove(file_path)
                print(f"Deleted: {file_path}")
            print("All selected .txt files deleted.")
        else:
            print("Operation canceled. No files were deleted.")
    
    except Exception as e:
        print(f"An error occurred: {e}")

def menu():
    while True:
        print("\nMenu:")
        print("1. DNS")
        print("2. Discover")
        print("3. Attack")
        print("4. Other stuff")
        print("5. Report Generation")
        print("6. File Cleanup")
        print("7. Exit")

        
        choice = input("Enter your choice: ")

        if choice == '1':
            recon()
        elif choice == '2':
            discover()
        elif choice == '3':
            attacksubmenu()
        elif choice == '4':
            submenu()
        elif choice == '5':
            reportgen()
        elif choice == '6':
            cleanup()
        elif choice == '7':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    menu()
