# Stealing Web Application Credentials by Hooking Input Fields

Simple and effective technique for stealing web application passwords from compromised systems by hooking input `password` fields in HTML applications.

## When is it useful?

The technique is useful and can be executed when:

* You have RDP'd into the compromised system, where a target user utilizes some web application to perform his/her daily duties, that is of interest to you
* You need to get access credentials to that application for whatever reason and don't want/can't use a keylogger
* The target web application is still running and the logon screen is present. 

{% hint style="info" %}
If application session is not expired, log out so you are presented with the logon screen.
{% endhint %}

## Hooking the Password Field

### Events

Password fields in web applications are `input` fields with attribute `type` set to `password` as shown below \(HTML markup snippet from github.com\):

![](../../.gitbook/assets/image%20%28411%29.png)

All HTML elements can respond to various types of events. For example, input fields can respond to events such `onFocus` \(when an element gets focus\), `onBlur` \(when an element loses focus\) and many other events amongst which are various keyboard events `onKeyPress`, `onKeyDown`, and `onKeyUp`. For more about events - [https://www.w3schools.com/tags/ref\_eventattributes.asp](https://www.w3schools.com/tags/ref_eventattributes.asp)

### Hooking

Below is a simple JavaScript/jQuery code that hooks HTML inputs of type `password`:

```javascript
t=""; $('input[type="password"]').onkeypress = function (e) { t+=e.key; console.log(t); localStorage.setItem("pw", t); } 
```

{% hint style="info" %}
The above code only captures the password field, but username could be captured the same way.
{% endhint %}

The above code needs to be executed in the context of the target web application. Once executed, it performs the following:

* selects an input field of type `password` inside the HTML page
* binds the `onKeyPress` event handler with a function that processes captured the keys a user types into the `password` field
* the function prints out captured keys into the browser's console view
* additionally, the function stores the password into the browser's `localStorage` in a key called `pw`

{% hint style="warning" %}
If the user closes the browser or even a tab with the web application you are targeting, the hooks will be cleared and the binding processes will need to be repeated again.
{% endhint %}

## Demo

Below shows the hooking in action inside the Chrome dev tools \(can be done the same way in IE and FF\):

* Inside the dev console \(F12 to open/close\), the hooking code is inserted
* Dummy password is typed into the password field
* Dummy password is being printed to the dev console
* Dummy password is saved into application's localStorage `pw` key

![](../../.gitbook/assets/hooking-web-password-fields%20%281%29.gif)

## Reading Captured Password

You've hooked the password field, stopped the operation for the day and then resumed the next day and you want to check if the password got captured. There are at least a couple of ways of doing it.

### LocalStorage via Console

You could again RDP into the compromised system, open up Chrome dev tools \(F12\) and in the console, type:

```javascript
localStorage.pw
```

![Password that was captured earlier](../../.gitbook/assets/image%20%28127%29.png)

### LocalStorage Files on the Disk

The `localStorage` information is also stored on the disk. For Chrome, the files of are located here  C:\Users\spotless\AppData\Local\Google\Chrome\User Data\Default\Local Storage\leveldb.

Below shows that our `password` \(orange\) was stored inside the file `009668.ldb` \(blue\), inside the `localStorage` key `pw` \(lime\):

![](../../.gitbook/assets/image%20%28342%29.png)

{% hint style="info" %}
Use an obscure, but descriptive localStorage key to store the captured password in. It will make it easier for you to retrieve the stored password later.
{% endhint %}

I have not worked out yet how Chrome decides which file the localStorage information will be saved to, so if you are reading this and know, do let me know.

### Exfiltration

The initial code could be easily adapted to exfiltrate the password to an attacker controlled web server on each key press, taking away the need to RDP to the target system or fiddling with localStorage files.

{% hint style="info" %}
Use encrypted communications when transferring the password out of the compromised environment.
{% endhint %}

## Detection

Currently, I do not know a resilient method to  detect this activity, but for a start, one of the .ldb files \(009667.ldb in my case\) in C:\Users\spotless\AppData\Local\Google\Chrome\User Data\Default\Local Storage\leveldb, contains the actual hooking code we inserted into Chrome's dev console. 

Highlighted in lime is the HTML `password` field selector in jQuery and the event name `onKeyPress` that is being hooked:

![](../../.gitbook/assets/image%20%28310%29.png)

...suggesting that one could monitor C:\Users\&lt;user&gt;\AppData\Local\Google\Chrome\User Data\Default\Local Storage\leveldb for files that contain jQuery/vanilla JavaScript `password` field selectors and keywords `onkeypress`, `onkeyup`, `onkeydown` in the same file. 

If you come up with a better idea, let me know.

