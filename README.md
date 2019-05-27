# health-ip
Checks Open proxies health via various parameters such as anonymity (exposed public IP or not), resolved dns or not and obviously 
Http status.
* Gives count of good, bad and proxies which exposes our ip.
* Proxies which fails consecutively five times are discared.
* Implemented Rotating Logging to log exceptions, start and end of daily check threads etc.
* Implemented *multithreading* to handle *IO* request and used *redis queue* for storing the responses.
* Listener to this response queue uses *blocking right pop* to get the response and save it in *Mongodb*
#### Note: Although pushed it in python 3 but haven't tested it for python 3.
