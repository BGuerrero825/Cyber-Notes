Fuzz for errors - Use Network Debugger (Inspect Page) to fuzz input in GETs and POSTs to receive some error feedback from the webpage.

Path manipulation - Use Path Traversal escapes(../../etc/password) to navigate out of page's script file location and to core file locations.

Be aware of url encoding to bypass some input filtering. Ex. %2F for / and %00 (null terminator) to truncate at the end of your input (and avoid automatic extension additions).

../ - escape up a directory
%00 - terminator to throw away rest of the request (if script appends data on after)
&x, ?x= - parameterize the rest of the request (again, to throw it away) 
%2F - for /
%20 - for space