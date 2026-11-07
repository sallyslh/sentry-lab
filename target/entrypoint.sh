#!/bin/sh
/usr/sbin/sshd
exec nginx -g 'daemon off;'
