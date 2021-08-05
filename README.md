# UserWeb

This is a web based front end to manage users configured in an LDAP server.  UserWeb is intended to provide an easy way to add and remove both full users and guests as a part of my ongoing attempt to configure 
WPA2-Enterprise with individual user and guest accounts on my home network.

In order for this to be minimally viable it needs the ability for administrators to add full user accounts, and for full user accounts to be able to add new guest accounts.

## Requirements

UserWeb us built around and requires the following

 - Python 3
 - [Pyramid](https://trypyramid.com/)
 - [usermanagment](https://github.com/tdegenko/Ldap-User-Management)
	 + Which is in turn built around [python-ldap](https://github.com/python-ldap/python-ldap)