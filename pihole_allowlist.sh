#!/bin/bash
#
clear
echo "
 _____             _         _    _          _                                   
|     |___ ___ ___| |_ ___ _| |  | |_ _ _   |_|                                  
|   --|  _| -_| .'|  _| -_| . |  | . | | |   _                                   
|_____|_| |___|__,|_| |___|___|  |___|_  |  |_|                                  
                                     |___|                                       
                                                                                 
 _____ _       _     _           _              _____    __    _____             
|     | |_ ___|_|___| |_ ___ ___| |_ ___ ___   |     |__|  |  |   __|___ ___ _ _ 
|   --|   |  _| |_ -|  _| . | . |   | -_|  _|  | | | |  |  |  |  |  |  _| .'| | |
|_____|_|_|_| |_|___|_| |___|  _|_|_|___|_|    |_|_|_|_____|  |_____|_| |__,|_  |
                            |_|                                             |___|

 https://discourse.pi-hole.net/t/commonly-whitelisted-domains/212/12

This really is meant to be run under Rasbian / PiHole / Ubuntu 16.04 LTS +

Version:  0.0.41
Last Updated:  6/2/2024

"
#--------------------------
pihole -w github.com raw.githubusercontent.com

#--- General ---
pihole -w cloudflare.com  1dot1dot1dot1.cloudflare-dns.com  cloudflare-dns.com

#-- DNS DoH https://github.com/curl/curl/wiki/DNS-over-HTTPS#publicly-available-servers  --
### ALWAYS BLOCK:  use-application-dns.net   - NEVER ALLOW IT THRU!
#pihole -w mozilla.cloudflare-dns.com dns.google dns.quad9.net doh.powerdns.org

#-- NTP ---
pihole -w time.cloudflare.com time.google.com nist.gov pool.ntp.org

#--- Google
pihole -w google.com www.google.com classroom.google.com docs.google.com clients2.google.com clients3.google.com clients4.google.com dl.google.com android.clients.google.com fonts.gstatic.com fonts.gstatic.com
pihole -w connectivitycheck.android.com connectivitycheck.gstatic.com
pihole -w ajax.googleapis.com

#--- Microsoft
# Windows uses this to verify connectivity to Internet
pihole -w www.msftncsi.com
### Windows Defender
wdcp.microsoft.com
wdcpalt.microsoft.com
tsfe.trafficshaping.dsp.mp.microsoft.com
# The rest
pihole -w outlook.office365.com products.office.com c.s-microsoft.com i.s-microsoft.com login.live.com protection.outlook.com
pihole -w clientconfig.passport.net officeclient.microsoft.com
pihole -w v10.events.data.microsoft.com v10.vortex-win.data.microsoft.com settings-win.data.microsoft.com 
pihole -w s.gateway.messenger.live.com ui.skype.com pricelist.skype.com apps.skype.com m.hotmail.com s.gateway.messenger.live.com sa.symcb.com symcb.com 
pihole -w settings-win.data.microsoft.com 
pihole -w v10.vortex-win.data.microsoft.com mobile.pipe.aria.microsoft.com
pihole -w msftncsi.com www.msftncsi.com ipv6.msftncsi.com

#-- pinterest
pihole -w pinterest.com policy.pinterest.com trk.pinterest.com trk2.pinterest.com api.pinterest.com v.pinimg.com prod.pinterest.global.map.fastly.net s-pinimg-com.gslb.pinterest.com i.pinimg.com.gslb.pinterest.com 
#-- Xbox
# pihole -w xbox.ipv6.microsoft.com device.auth.xboxlive.com www.msftncsi.com title.mgt.xboxlive.com xsts.auth.xboxlive.com title.auth.xboxlive.com ctldl.windowsupdate.com attestation.xboxlive.com xboxexperiencesprod.experimentation.xboxlive.com xflight.xboxlive.com cert.mgt.xboxlive.com xkms.xboxlive.com def-vef.xboxlive.com notify.xboxlive.com help.ui.xboxlive.com licensing.xboxlive.com eds.xboxlive.com www.xboxlive.com v10.vortex-win.data.microsoft.com settings-win.data.microsoft.com

#--- Facebook
pihole -w www.facebook.com facebook.com static.xx.fbcdn.net fbcdn.net creative.ak.fbcdn.net scontent-lga3-1.xx.fbcdn.net edge-chat.facebook.com external-lhr0-1.xx.fbcdn.net external-lhr1-1.xx.fbcdn.net external-lhr10-1.xx.fbcdn.net external-lhr2-1.xx.fbcdn.net external-lhr3-1.xx.fbcdn.net external-lhr4-1.xx.fbcdn.net external-lhr5-1.xx.fbcdn.net external-lhr6-1.xx.fbcdn.net external-lhr7-1.xx.fbcdn.net external-lhr8-1.xx.fbcdn.net external-lhr9-1.xx.fbcdn.net fbcdn-creative-a.akamaihd.net scontent-lhr3-1.xx.fbcdn.net scontent.xx.fbcdn.net scontent.fgdl5-1.fna.fbcdn.net graph.facebook.com connect.facebook.com cdn.fbsbx.com

#--- Twitter
pihole -w twitter.com www.twitter.com mobile.twitter.com analytics.twitter.com t.co

#-- Plex
pihole -w plex.tv tvdb2.plex.tv pubsub.plex.bz proxy.plex.bz proxy02.pop.ord.plex.bz cpms.spop10.ams.plex.bz meta-db-worker02.pop.ric.plex.bz meta.plex.bz tvthemes.plexapp.com.cdn.cloudflare.net tvthemes.plexapp.com 106c06cd218b007d-b1e8a1331f68446599e96a4b46a050f5.ams.plex.services meta.plex.tv cpms35.spop10.ams.plex.bz proxy.plex.tv metrics.plex.tv pubsub.plex.tv status.plex.tv www.plex.tv node.plexapp.com nine.plugins.plexapp.com staging.plex.tv app.plex.tv o1.email.plex.tv  o2.sg0.plex.tv dashboard.plex.tv

#-- Apple
pihole -w itunes.apple.com appleid.apple.com ocsp.apple.com
pihole -w captive.apple.com gsp1.apple.com www.apple.com www.appleiphonecell.com

#-- Snapchat
#pihole -w app-analytics.snapchat.com sc-analytics.appspot.com cf-st.sc-cdn.net

#--- Ads that are good
pihole -w weeklyad.target.com m.weeklyad.target.com weeklyad.target.com.edgesuite.net api.target.com redsky.target.com profile.target.com 

#--- Amazon
pihole -w amazon.com s3.amazonaws.com fls-na.amazon.com unagi-na.amazon.com mas-ssr-ad.amazon.com mas-ext.amazon.com device-metrics-us.amazon.com msh.amazon.com

#-- Others
pihole -w gravatar.com bit.ly godaddy.com secureserver.net img1.wsimg.com sdk.split.io
pihole -w thetvdb.com
pihole -w themoviedb.com
pihole -w medium.com
pihole -w spclient.wg.spotify.com apresolve.spotify.com
pihole -w ocsp2.apple.com ocsp2.g.aaplimg.com ocsp2-lb.apple.com.akadns.net ocsp.godaddy.com ocsp.godaddy.com ocsp.sca1b.amazontrust.com ocsp.pki.goog ocsp.digicert.com.lan ocsp.usertrust.com crl4.digicert.com  cs9.wac.phicdn.net 
pihole -w highcharts.com
pihole -w bflix.to
#-- podcasts (Security Now - Twit) 
pihole -w traffic.libsyn.com

#-- Charters.com
pihole -w yottaa.net
#-- Starbucks mobile app
pihole -w device-api.urbanairship.com sbux-dl.urbanairship.com

#--Captive-portal tests (connectivitycheck)
pihole -w connectivitycheck.android.com android.clients.google.com clients3.google.com connectivitycheck.gstatic.com

#-- School ---
pihole -w goguardian.com ip.goguardian.com quiddity.goguardian.com panther.goguardian.com x3-policy-maker.goguardian.com waluigi.goguardian.com snat.goguardian.com play-button.goguardian.com 

#-- SmartTV's ---
pihole -w cdn.samsungcloudsolution.com  samsungcloudsolution.com  lcprd1.samsungcloudsolution.net  osb.samsungqbe.com  osb-apps-v2.samsungqbe.com  lcprd1.samsungcloudsolution.net  log-config.samsungacr.com
