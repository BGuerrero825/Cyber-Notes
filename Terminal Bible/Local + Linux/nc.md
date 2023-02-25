*creates a connection to an IP on a specific port, or listens on a specific port*

nc **IP** -p **port**
nc -lvnp **port**

-l: listener
-v: verbose output
-n: numeric-only IPs, no DNS
-p: specify port #