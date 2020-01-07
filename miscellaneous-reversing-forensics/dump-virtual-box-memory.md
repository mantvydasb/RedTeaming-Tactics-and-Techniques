---
description: >-
  A quick reminder of one of the ways of how to dump memory of a VM running on
  VirtualBox in Linux environment.
---

# Dump Virtual Box Memory

## List Available VMs

```erlang
cd "C:\Program Files\Oracle\VirtualBox\"
.\VBoxManage.exe list vms

...
"win1002 debugee" {5f176ebb-a0cc-4dc7-9c6f-988fcbcca867}
...
```

## Enable Debug Mode

{% code title="linux host" %}
```bash
mantvydas@~: virtualbox --startvm 'yourVMName or VM UUID' --dbg
```
{% endcode %}

## Dump VM Memory

Launch the VirtualBox debug console by navigating to "Debug" menu an select "Command Line":

![](../.gitbook/assets/vbox-menu.png)

Once you select "Command Line", you will be presented with a console that looks like this:

![memory dump will be a raw file dumped to /home/youruser directory](../.gitbook/assets/vbox-debug.png)

To create a memory dump, issue the below command \(also highlighted in the above graphic\):

{% code title="VM@virtualbox" %}
```text
VBoxDbg> .pgmphystofile 'w7-nc-shell.bin'
```
{% endcode %}

## Persistence

If you want the debug options to be always available, you can:

* export `VBOX_GUI_DBG_ENABLED=true` before launching the VM or
* put export `VBOX_GUI_DBG_ENABLED=true` in your `.bashrc` or `/etc/environment` 

