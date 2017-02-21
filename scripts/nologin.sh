#!/bin/bash

for user in `awk -F: '($3 &lt; 500) {print $1 }' /etc/passwd` ; do
if [ $user != &amp;quot;root&amp;quot; ]; then
usermod -L $user
if [ $user != &amp;quot;sync&amp;quot; ] &amp;&amp; [ $user != &amp;quot;shutdown&amp;quot; ] &amp;&amp; [ $user != &amp;quot;halt&amp;quot; ]; then
usermod -s /sbin/nologin $user
fi
fi
done
Linux Custom Ob
