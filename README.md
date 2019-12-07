# suricata-sandbox
~~~
vagrant@vg-suricata-01:~$ sudo suricata-update
vagrant@vg-suricata-01:~$ sudo suricata-update update-sources
vagrant@vg-suricata-01:~$ sudo ethtool -K eth1 tso off
vagrant@vg-suricata-01:~$ sudo ethtool -K eth1 tx off
vagrant@vg-suricata-01:~$ sudo ethtool -K eth1 gro off

vagrant@vg-suricata-01:~$ sudo cp /vagrant/custom_rules/my.rules /var/lib/suricata/rules
vagrant@vg-suricata-01:~$ sudo cp /vagrant/custom_rules/test-ddos.rules /var/lib/suricata/rules
vagrant@vg-suricata-01:~$ sudo ls /var/lib/suricata/rules
my.rules  suricata.rules  test-ddos.rules

vagrant@vg-suricata-01:~$ sudo suricata -D -c /etc/suricata/suricata.yaml -i eth1
7/12/2019 -- 11:00:35 - <Notice> - This is Suricata version 5.0.0 RELEASE running in SYSTEM mode


# smoketesting
vagrant@vg-suricata-03:~$ sudo hping3 -S -p 80 --flood --rand-source vg-suricata-01
HPING vg-suricata-01 (eth1 192.168.18.9): S set, 40 headers + 0 data bytes
hping in flood mode, no replies will be shown

# monitoring
vagrant@vg-suricata-01:~$ sudo tail -f /var/log/suricata/fast.log
vagrant@vg-suricata-01:/var/log/suricata$ cd /var/log/suricata && tail -f http.log stats.log

~~~
~~~
The configuration file
/etc/suricata/suricata.yaml

$ sudo cat /etc/suricata/suricata.yaml
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]" # internal network to be proctected
    EXTERNAL_NET: "!$HOME_NET"
~~~
~~~
You can now start suricata by running as root something like:
  /usr/bin/suricata -c /etc/suricata/suricata.yaml -i eth0

If a library like libhtp.so is not found, you can run suricata with:
  LD_LIBRARY_PATH=/usr/lib /usr/bin/suricata -c /etc/suricata/suricata.yaml -i eth0

The Emerging Threats Open rules are now installed. Rules can be
updated and managed with the suricata-update tool.

For more information please see:
  https://suricata.readthedocs.io/en/latest/rule-management/index.html

make[1]: Leaving directory '/tmp/suricata-5.0.0'
~~~
~~~
vagrant@vg-suricata-01:~$ sudo /usr/bin/suricata -c /etc/suricata/suricata.yaml -i eth1
6/12/2019 -- 23:49:49 - <Notice> - This is Suricata version 5.0.0 RELEASE running in SYSTEM mode
6/12/2019 -- 23:49:49 - <Warning> - [ERRCODE: SC_ERR_INVALID_ARGUMENT(13)] - eve-log dns version not found, forcing it to version 2
6/12/2019 -- 23:49:49 - <Warning> - [ERRCODE: SC_ERR_INVALID_ARGUMENT(13)] - eve-log dns version not found, forcing it to version 2
6/12/2019 -- 23:50:04 - <Notice> - all 2 packet processing threads, 4 management threads initialized, engine started.
~~~
~~~
 download the Emerging Threats Open ruleset
 sudo suricata-update
 download the ruleset into
 /var/lib/suricata/rules/

 $ sudo suricata-update update-sources
 6/12/2019 -- 23:56:24 - <Info> -- Using data-directory /var/lib/suricata.
 6/12/2019 -- 23:56:24 - <Info> -- Using Suricata configuration /etc/suricata/suricata.yaml
 6/12/2019 -- 23:56:24 - <Info> -- Using /usr/share/suricata/rules for Suricata provided rules.
 6/12/2019 -- 23:56:24 - <Info> -- Found Suricata version 5.0.0 at /usr/bin/suricata.
 6/12/2019 -- 23:56:24 - <Info> -- Downloading https://www.openinfosecfoundation.org/rules/index.yaml
 6/12/2019 -- 23:56:25 - <Info> -- Saved /var/lib/suricata/update/cache/index.yaml

what is available
$ sudo suricata-update list-sources

enable rules that are disabled by default
/etc/suricata/enable.conf
disable rules
/etc/suricata/disable.conf

~~~
custom rulesets
~~~
default-rule-path: /var/lib/suricata/rules

rule-files:
  - suricata.rules
# Custom Test rules
  - test-ddos.rules  
  - my.rules

disable packet offload features on the network interface on which Suricata is listen
ethtool -K eth1 gro off lro off

$ sudo ethtool -K eth1 gro off lro off
Cannot change large-receive-offload

$ ethtool -k eth1 | grep large
large-receive-offload: off [fixed]

ethtool -K eth1 tso off
ethtool -K eth1 tx off
ethtool -K eth1 gro off

various modes in which Suricata can run
suricata --list-runmodes

run Suricata in PCAP live mode
  suricata -D -c /etc/suricata/suricata.yaml -i eth1

Tests for errors rule Very recommended --init-errors-fatal
sudo suricata -c /etc/suricata/suricata.yaml -i eth1 --init-errors-fatal

Suricata logs on Suricata host
tail -f /var/log/suricata/fast.log

tail -f /var/log/suricata/http.log
tail -f /var/log/suricata/stats.log

cd /var/log/suricata && tail -f http.log stats.log
~~~
smoketesting suricata
~~~
remote client

perform SYN FLOOD attack against Suricata server
hping3 -S -p 80 --flood --rand-source vg-suricata-01

Nmap scan against Suricata server
nmap -sS -v -n -A vg-suricata-01 -T4

perform SSH connection attemt from the remote machine
ssh vg-suricata-01

perform test attack against Suricata server
nikto -h vg-suricata-01 -C all


~~~
