winsock.h recvfrom
https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recvfrom
```
int recvfrom(
  [in]                SOCKET   s,
  [out]               char     *buf,
  [in]                int      len,
  [in]                int      flags,
  [out]               sockaddr *from,
  [in, out, optional] int      *fromlen
);
```
- `*buf` output buffer for incoming data
- `*from` optional arg specifying source address of connection
Return: Number of bytes received, or -1 if error