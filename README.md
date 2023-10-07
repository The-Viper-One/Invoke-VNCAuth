# Invoke-VNCAuth

Simple Powershell script which can be used to scan CIDR ranges and Active Directory for systems running VNC that do not require authentication to connect. 

# Load into memory
```
IEX(New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/The-Viper-One/Invoke-VNCAuth/main/Invoke-VNCAuth.ps1")
```

# Usage
At minimum -Targets is required, otherwise Invoke-VNCAuth supports optional parameters as shown below
```
# Mandatory parameters
Invoke-VNCAuth -Targets DC01.security.local  # Specifc name or IP
Invoke-VNCAuth -Targets All                  # All enabled systems in Acitve Directory
Invoke-VNCAuth -Targets Servers              # All servers in Active Directory
Invoke-VNCAuth -Targets 10.10.10.0/24        # Scan an entire CIDR range

# Optional Parameters
-Threads 10                                  # Specify number of threads to run
-SuccessOnly                                 # Show only successful results
-Domain                                      # Run against an alternate domain (Default is $env:userdnsdomain)
-Port                                        # Specify alternate port (Default is 5900)
```

# Images

![image](https://github.com/The-Viper-One/Invoke-VNCAuth/assets/68926315/22cef3ed-1f36-438e-9098-4fc400b0183b)
