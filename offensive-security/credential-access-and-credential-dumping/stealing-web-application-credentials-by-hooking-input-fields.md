---
description: 'Credential Access, Keylogger'
---

# Pulling Web Application Passwords by Hooking  HTML Input Fields

A technique for stealing web application passwords from compromised systems by hooking input `password` fields in HTML applications and effectively implementing a simple keylogger.

## When is it useful?

The technique is useful and can be executed when:

* You have RDP'd into the compromised system, where a target user utilizes some web application to perform his/her daily duties, that is of interest to you
* You need to get access credentials to that application for whatever reason \(i.e collecting passwords for re-use or looking to see how the user usually constructs passwords, etc\)

  and can't/don't want to use a keylogger for whatever reason

* Tab with the target web application is open

## Hooking the Password Field

### Events

Password fields in web applications are `input` fields with attribute `type` set to `password` as shown below:

![HTML markup snippet from github.com](../../.gitbook/assets/image%20%28516%29.png)

All HTML elements can respond to various types of events ****and execute code when those occur. For example, input fields can respond to events such `onFocus` \(when an element gets focus\), `onBlur` \(when an element loses focus\) and many other events amongst which are various keyboard events `onKeyPress`, `onKeyDown`, and `onKeyUp`. 

For more about events - [https://www.w3schools.com/tags/ref\_eventattributes.asp](https://www.w3schools.com/tags/ref_eventattributes.asp)

### Hooking

Below is a simple JavaScript/jQuery code that hooks HTML `password` fields:

```javascript
t=""; $('input[type="password"]').onkeypress = function (e) { t+=e.key; console.log(t); localStorage.setItem("pw", t); } 
```

{% hint style="info" %}
The above code only captures the password field, but username could be captured the same way.
{% endhint %}

The above code needs to be executed in the context of the target web application you want to capture the password for. Once the above code snippet is executed, it performs the following:

* selects an input field of type `password` inside the HTML page of the target web application
* binds the `onKeyPress` event handler with a function that processes captured keys a user types into the `password` field when logging in to the target application
  * the function prints out captured keys into the browser's console view for this demo's purposes
  * the function stores the captured password in browser's `localStorage` key `pw`

{% hint style="warning" %}
If the user closes the browser or even a tab with the web application you are targeting before the password was captured, the hooks will be cleared and the binding / hooking processes will need to be repeated again.
{% endhint %}

## Demo

Below shows the hooking in action inside the Chrome dev tools \(can be done the same way in IE and FF\):

* Inside the dev console \(F12 to open/close\), the hooking code is inserted
* Dummy password is typed into the password field
* Dummy password is being printed to the dev console
* Dummy password is saved into application's localStorage `pw` key

![](../../.gitbook/assets/hooking-web-password-fields%20%281%29.gif)

## Reading Captured Password

Say, you've hooked the password field, stopped the operation for the day and then resumed it next day and now you want to check if the password got captured - there are at least a couple of ways of doing it.

### LocalStorage via Console

You could again RDP into the compromised system, open up Chrome dev tools \(F12\) and in the console, type:

```javascript
localStorage.pw
```

![Password that was captured earlier](../../.gitbook/assets/image%20%28163%29.png)

...or simply navigate to the dev console and open Application &gt; LocalStorage section as shown in the above gif.

### LocalStorage Files on the Disk

The `localStorage` information is also stored on the disk. For Chrome, the files of are located here  C:\Users\spotless\AppData\Local\Google\Chrome\User Data\Default\Local Storage\leveldb and is stored in a file XXXXXX.log. In my case, it was the file `009691.log`

Below shows `password` \(lime\) for github.com \(blue\) stored in `localStorage` key `pw` \(orange\):

![009691.log](../../.gitbook/assets/image%20%28403%29.png)

{% hint style="info" %}
Use an obscure, but descriptive localStorage key to store the captured password in. It will make it easier for you to retrieve the stored password later.
{% endhint %}

### Exfiltration

The initial code could be easily adapted to exfiltrate the password to an attacker controlled web server on each key press, taking away the need to RDP to the target system or fiddling with localStorage files.

{% hint style="info" %}
Use encrypted communications when transferring the password out of the compromised environment.
{% endhint %}

## Detection

For a start, the .log file \(009691.log in my case\) in C:\Users\spotless\AppData\Local\Google\Chrome\User Data\Default\Local Storage\leveldb, contains the actual hooking code we inserted into Chrome's dev console for the target web application: 

![](../../.gitbook/assets/image%20%28255%29.png)

...suggesting that one could monitor C:\Users\&lt;user&gt;\AppData\Local\Google\Chrome\User Data\Default\Local Storage\leveldb for \*.log files that contain jQuery/vanilla JavaScript `password` field selector and keywords `onkeypress`, `onkeyup`, `onkeydown`. 

