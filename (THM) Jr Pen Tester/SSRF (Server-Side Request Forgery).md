Some web hosts connect back to another server for information, authentication, etc. We can manipulate URL requests sent to the web host to access resources on the server we weren't intended to see

../../ escapes can be used once again in directory entry fields

ex. use... `?server=` field to redirect from intended page to an id=9 with:
`?server=server.website.thm/flag?id=9&x`
the `&x` parameterized the auto appended part of the request, throwing it away, and letting us to nav to our intended page

SSRF Locations:
full URLs used as a parameter in address bar
hidden field in a form
partial URL as parameter (ex. form?server=api)
path of URL as parameter (ex. form?dst=/forms/contact)