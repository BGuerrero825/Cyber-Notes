Pass packet from proxy into intruder
Sniper - try one payload set in one or multiple locations
Battering Ram - try one playload set in multiple locations at the same time
Pitchfork - iterate through multiple payload sets simultaneously in multiple locations (ex. credential stuffings - enter associated user and pass at the same time, stepping down each as you go)
Cluster Bomb - Try every combination of first set payloads in first location, second set playloads in second location, etc. (ex. you dont have username and pass associations, just the data)

CSRF Practical:
- Use intruder with a cred stuffing attack to bypass login. 
- BUT there is CSRF prevention tokens and session cookies :(
- Pass the login authentication packet to Intruder as normal and set up the username and password fields for Pitchfork cred stuffing.
- Then, go to Project options -> Sessions
- Add a new Macro (repeatable "user-like" action) to navigate to target webpage, therefore grabbing a new session cookie and loginToken
- Create a new Session Handling Rule and add in the Macro, set macro to update only the specified request parameter ("loginToken") and cookie ("session")
- Check Scope to ensure it is set to affect packets sent through Intruder attacks and affects all URLs accessed in the attack (at least for this use case)
- Start Intruder Attack
- Profit