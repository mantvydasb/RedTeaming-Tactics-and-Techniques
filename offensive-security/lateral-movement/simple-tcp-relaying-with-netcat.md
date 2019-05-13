# Simple TCP Relaying with NetCat

This is a simple lab that looks at how to setup a traffic relay using netcat.

We are amining to create a relay between ports 4444 and 22 - any traffic coming to 4444 will be redirected to port 22.

```bash
# setup listener on port 22
nc -lvvp 22

# setup listener on port 4444 and direct stdout to port 22 using netcat
nc -lvvp 4444 | nc localhost 22

# send a string "test" to port 4444 using netcat
echo test | nc localhost 4444
```

Below is an animated demo of how this all works in action:

![](../../.gitbook/assets/peek-2019-01-11-11-06.gif)

