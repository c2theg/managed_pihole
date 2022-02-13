# managed_pihole
Managed Pihole for Version 5.x

for the initial setup run this. 


sudo wget https://raw.githubusercontent.com/c2theg/managed_pihole/main/update_lists.sh && chmod u+x update_lists.sh && ./update_lists.sh && ./initial_setup.sh



<h2>Install Pi-Hole</h2>

Configure Raspberry PI using: <b>sudo raspi-config</b>

Install pi-hole as usual ( <b> curl -sSL https://install.pi-hole.net | bash </b> ) 
<br /><br />

<b>To configure it to maintain extra block and white lists, use the following script </b>
<br /><br />

wget https://raw.githubusercontent.com/c2theg/srvBuilds/master/raspi/update_pihole_lists.sh && chmod u+x update_pihole_lists.sh && sudo ./update_pihole_lists.sh


<h3>Static IP </h3>
wget https://raw.githubusercontent.com/c2theg/srvBuilds/master/configs/01-netcfg.yaml && mv 01-netcfg.yaml /etc/netplan/00-installer-config.yaml
cd /etc/netplan/



<h3>DoH on Pi Hole</h3>
wget https://raw.githubusercontent.com/c2theg/srvBuilds/master/install_doh_pihole.sh && chmod u+x install_doh_pihole.sh && sudo ./install_doh_pihole.sh


<h3>OpenDNS account, linux updater </h3>
wget https://raw.githubusercontent.com/c2theg/srvBuilds/master/raspi/install_opendns.sh && chmod u+x install_opendns.sh && sudo ./install_opendns.sh
