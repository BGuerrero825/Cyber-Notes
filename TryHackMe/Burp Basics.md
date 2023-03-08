Burp proxy defaults to port 8080
Portswigger Certificate Authority:
If we try to intercept https traffic we get a warning because Burp uses Portswigger as a Certificate Authority which isn't recognized by default on the browser. 
http://burp/cert -> download cacert.der -> browser certificates settings -> View Certificates -> Authorities -> Import cacert.der -> check Trust this CA to identify websites.
Scoping:
Limits the amount of traffic stopped by the proxy by specifying hosts to stop or allow. Target -> Site Map -> Add to scope (log out of scope proxy traffic: off) -----> Proxy -> Options -> And | URL | Is in target scope
Site Map: Builds out a directory of a website while you browse through the pages. Look for strange pages / resources.
Attack Example:
A support ticket page allows for user input but only validates on the client side. Using Burp, I send a legit entry then intercept the outbound traffic and change the email input to a <script>...</script> and execute my code.