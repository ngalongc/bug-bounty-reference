# Bug Bounty Reference

A list of bug bounty write-up that is categorized by the bug nature, this is inspired by https://github.com/djadmin/awesome-bug-bounty

# Introduction

I have been reading for Bug Bounty write-ups for a few months, I found it extremely useful to read relevant write-up when I found a certain type of vulnerability that I have no idea how to exploit. Let say you found a RPO (Relativce Path Overwrite) in a website, but you have no idea how should you exploit that, then the perfect place to go would be [here](http://blog.innerht.ml/rpo-gadgets/). Or you have found your customer is using oauth mechanism but you have no idea how should we test it, the other perfect place to go would be [here](https://whitton.io/articles/obtaining-tokens-outlook-office-azure-account/)

My intention is to make a full and complete list of common vulnerability that are publicly disclosed bug bounty write-up, and let Bug Bounty Hunter to use this page as a reference when they want to gain some insight for a particular kind of vulnerability during Bug Hunting, feel free to submit pull request. Okay, enough for chit-chatting, let's get started. 


- [XSSI](#xssi)
- [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
- [Brute Force](#brute-force)
- [SQL Injection (SQLi)](#sql-injection)
- [External XML Entity Attack (XXE)](#xxe)
- [Remote Code Execution (RCE)](#remote-code-execution)
  - [Deserialization](#deserialization)
  - [Image Tragick](#image-tragick)
- [Cross-Site Request Forgery (CSRF)](#csrf)
- [Insecure Direct Object Reference (IDOR)](#direct-object-reference-idor)
- [Stealing Access Token](#stealing-access-token)
  - [Google Oauth Login Bypass](#google-oauth-bypass)
- [Server Side Request Forgery (SSRF)](#server-side-request-forgery-ssrf)
- [Unrestricted File Upload](#unrestricted-file-upload)
- [Race Condition](#race-condition)
- [Business Logic Flaw](#business-logic-flaw)
- [Authentication Bypass](#authentication-bypass)
- [HTTP Header Injection](#http-header-injection)
- [Email Related](#email-related)
- [Money Stealing](#money-stealing)
- [Miscellaneous](#miscellaneous)

### Cross-Site Scripting (XSS)

- [Sleeping stored Google XSS Awakens a $5000 Bounty](https://blog.it-securityguard.com/bugbounty-sleeping-stored-google-xss-awakens-a-5000-bounty/) by Patrik Fehrenbach
- [RPO that lead to information leakage in Google](http://blog.innerht.ml/rpo-gadgets/) by filedescriptor
- [God-like XSS, Log-in, Log-out, Log-in](https://whitton.io/articles/uber-turning-self-xss-into-good-xss/) in Uber by Jack Whitton   
- [An XSS on Facebook via PNGs & Wonky Content Types](https://whitton.io/articles/xss-on-facebook-via-png-content-types/) by Jack Whitton
  - he is able to make stored XSS from a irrelevant domain to main facebook domain 
- [Stored XSS in *.ebay.com](https://whitton.io/archive/persistent-xss-on-myworld-ebay-com/) by Jack Whitton
- [Complicated, Best Report of Google XSS](https://sites.google.com/site/bughunteruniversity/best-reports/account-recovery-xss) by Ramzes
- [Tricky Html Injection and Possible XSS in sms-be-vip.twitter.com](https://hackerone.com/reports/150179) by secgeek
- [Command Injection in Google Console](http://www.pranav-venkat.com/2016/03/command-injection-which-got-me-6000.html) by Venkat S
- [Facebook's Moves - OAuth XSS](http://www.paulosyibelo.com/2015/12/facebooks-moves-oauth-xss.html) by PAULOS YIBELO
- [Stored XSS in Google Docs (Bug Bounty)](http://hmgmakarovich.blogspot.hk/2015/11/stored-xss-in-google-docs-bug-bounty.html) by Harry M Gertos
- [Stored XSS on developer.uber.com via admin account compromise in Uber](https://hackerone.com/reports/152067) by James Kettle (albinowax)
- [Yahoo Mail stored XSS](https://klikki.fi/adv/yahoo.html) by Klikki Oy
- [Abusing XSS Filter: One ^ leads to XSS(CVE-2016-3212)](http://mksben.l0.cm/2016/07/xxn-caret.html) by Masato Kinugawa
- [Youtube XSS](https://labs.detectify.com/2015/06/06/google-xss-turkey/) by fransrosen
- [Best Google XSS again](https://sites.google.com/site/bughunteruniversity/best-reports/openredirectsthatmatter) - by Krzysztof Kotowicz
- [IE & Edge URL parsin Problem](https://labs.detectify.com/2016/10/24/combining-host-header-injection-and-lax-host-parsing-serving-malicious-data/) - by detectify
- [Google XSS subdomain Clickjacking](http://sasi2103.blogspot.sg/2016/09/combination-of-techniques-lead-to-dom.html)
- [Google Japan Book XSS](http://nootropic.me/blog/en/blog/2016/09/20/%E3%82%84%E3%81%AF%E3%82%8A%E3%83%8D%E3%83%83%E3%83%88%E3%82%B5%E3%83%BC%E3%83%95%E3%82%A3%E3%83%B3%E3%82%92%E3%81%97%E3%81%A6%E3%81%84%E3%81%9F%E3%82%89%E3%81%9F%E3%81%BE%E3%81%9F%E3%81%BEgoogle/) 
- [Flash XSS mega nz](https://labs.detectify.com/2013/02/14/how-i-got-the-bug-bounty-for-mega-co-nz-xss/) - by frans
- [xss in google IE, Host Header Reflection](http://blog.bentkowski.info/2015/04/xss-via-host-header-cse.html)
- [Years ago Google xss](http://conference.hitb.org/hitbsecconf2012ams/materials/D1T2%20-%20Itzhak%20Zuk%20Avraham%20and%20Nir%20Goldshlager%20-%20Killing%20a%20Bug%20Bounty%20Program%20-%20Twice.pdf)
- [xss in google by IE weird behavior](http://blog.bentkowski.info/2015/04/xss-via-host-header-cse.html)
- [xss in Yahoo Fantasy Sport](https://web.archive.org/web/20161228182923/http://dawgyg.com/2016/12/07/stored-xss-affecting-all-fantasy-sports-fantasysports-yahoo-com-2/)
- [xss in Yahoo Mail Again, worth $10000](https://klikki.fi/adv/yahoo2.html) by Klikki Oy
- [Sleeping XSS in Google](https://blog.it-securityguard.com/bugbounty-sleeping-stored-google-xss-awakens-a-5000-bounty/) by securityguard
- [Decoding a .htpasswd to earn a payload of money](https://blog.it-securityguard.com/bugbounty-decoding-a-%F0%9F%98%B1-00000-htpasswd-bounty/) by securityguard
- [Google Account Takeover](http://www.orenh.com/2013/11/google-account-recovery-vulnerability.html#comment-form)
- [AirBnb Bug Bounty: Turning Self-XSS into Good-XSS #2](http://www.geekboy.ninja/blog/airbnb-bug-bounty-turning-self-xss-into-good-xss-2/) by geekboy
- [Uber Self XSS to Global XSS](https://httpsonly.blogspot.hk/2016/08/turning-self-xss-into-good-xss-v2.html)
- [How I found a $5,000 Google Maps XSS (by fiddling with Protobuf)](https://medium.com/@marin_m/how-i-found-a-5-000-google-maps-xss-by-fiddling-with-protobuf-963ee0d9caff#.cktt61q9g) by Marin MoulinierFollow
- [Airbnb – When Bypassing JSON Encoding, XSS Filter, WAF, CSP, and Auditor turns into Eight Vulnerabilities](https://buer.haus/2017/03/08/airbnb-when-bypassing-json-encoding-xss-filter-waf-csp-and-auditor-turns-into-eight-vulnerabilities/) by Brett 
- [XSSI, Client Side Brute Force](http://blog.intothesymmetry.com/2017/05/cross-origin-brute-forcing-of-saml-and.html)  
- [postMessage XSS Bypass](https://hackerone.com/reports/231053)
- [XSS in Uber via Cookie](http://zhchbin.github.io/2017/08/30/Uber-XSS-via-Cookie/) by zhchbin
- [Stealing contact form data on www.hackerone.com using Marketo Forms XSS with postMessage frame-jumping and jQuery-JSONP](https://hackerone.com/reports/207042) by frans
- [XSS due to improper regex in third party js Uber 7k XSS](http://zhchbin.github.io/2016/09/10/A-Valuable-XSS/) 
- [XSS in TinyMCE 2.4.0](https://hackerone.com/reports/262230) by Jelmer de Hen
- [Pass uncoded URL in IE11 to cause XSS](https://hackerone.com/reports/150179)
- [Twitter XSS by stopping redirection and javascript scheme](http://blog.blackfan.ru/2017/09/devtwittercom-xss.html) by Sergey Bobrov 
- [Auth DOM Uber XSS](http://stamone-bug-bounty.blogspot.hk/2017/10/dom-xss-auth_14.html)
- [XSS in www.yahoo.com](https://www.youtube.com/watch?v=d9UEVv3cJ0Q&feature=youtu.be) 
- [Stored XSS, and SSRF in Google using the Dataset Publishing Language](https://s1gnalcha0s.github.io/dspl/2018/03/07/Stored-XSS-and-SSRF-Google.html)
- [Stored XSS on Snapchat](https://medium.com/@mrityunjoy/stored-xss-on-snapchat-5d704131d8fd)

### Brute Force
- [Web Authentication Endpoint Credentials Brute-Force Vulnerability](https://hackerone.com/reports/127844) by Arne Swinnen
- [InstaBrute: Two Ways to Brute-force Instagram Account Credentials](https://www.arneswinnen.net/2016/05/instabrute-two-ways-to-brute-force-instagram-account-credentials/) by Arne Swinnen
- [How I Could Compromise 4% (Locked) Instagram Accounts](https://www.arneswinnen.net/2016/03/how-i-could-compromise-4-locked-instagram-accounts/) by Arne Swinnen
- [Possibility to brute force invite codes in riders.uber.com](https://hackerone.com/reports/125505) by r0t
- [Brute-Forcing invite codes in partners.uber.com](https://hackerone.com/reports/144616) by Efkan Gökbaş (mefkan)

### SQL Injection
- [SQL injection in Wordpress Plugin Huge IT Video Gallery in Uber](https://hackerone.com/reports/125932) by glc
- [SQL Injection on sctrack.email.uber.com.cn](https://hackerone.com/reports/150156) by Orange Tsai
- [Yahoo – Root Access SQL Injection – tw.yahoo.com](http://buer.haus/2015/01/15/yahoo-root-access-sql-injection-tw-yahoo-com/) by Brett Buerhaus
- [Multiple vulnerabilities in a WordPress plugin at drive.uber.com](https://hackerone.com/reports/135288) by Abood Nour (syndr0me)
- [GitHub Enterprise SQL Injection](http://blog.orange.tw/2017/01/bug-bounty-github-enterprise-sql-injection.html) by Orange
- [Yahoo SQL Injection to Remote Code Exection to Root Privilege](http://www.sec-down.com/wordpress/?p=494) by Ebrahim Hegazy

### Stealing Access Token
- [Facebook Access Token Stolen](https://whitton.io/articles/stealing-facebook-access-tokens-with-a-double-submit/) by Jack Whitton - 
- [Obtaining Login Tokens for an Outlook, Office or Azure Account](https://whitton.io/articles/obtaining-tokens-outlook-office-azure-account/) by Jack Whitton

- [Bypassing Digits web authentication's host validation with HPP](https://hackerone.com/reports/114169) by filedescriptor
- [Bypass of redirect_uri validation with /../ in GitHub](http://homakov.blogspot.hk/2014/02/how-i-hacked-github-again.html?m=1) by Egor Homakov
- [Bypassing callback_url validation on Digits](https://hackerone.com/reports/108113) by filedescriptor
- [Stealing livechat token and using it to chat as the user - user information disclosure](https://hackerone.com/reports/151058) by Mahmoud G. (zombiehelp54)
- [Change any Uber user's password through /rt/users/passwordless-signup - Account Takeover (critical)](https://hackerone.com/reports/143717) by mongo (mongo)
- [Internet Explorer has a URL problem, on GitHub](http://blog.innerht.ml/internet-explorer-has-a-url-problem/) by filedescriptor.
- [How I made LastPass give me all your passwords](https://labs.detectify.com/2016/07/27/how-i-made-lastpass-give-me-all-your-passwords/) by labsdetectify
- [Steal Google Oauth in Microsoft](http://blog.intothesymmetry.com/2015/06/on-oauth-token-hijacks-for-fun-and.html)
- [Steal FB Access Token](http://blog.intothesymmetry.com/2014/04/oauth-2-how-i-have-hacked-facebook.html)
- [Paypal Access Token Leaked](http://blog.intothesymmetry.com/2016/11/all-your-paypal-tokens-belong-to-me.html?m=1)
- [Steal FB Access Token](http://homakov.blogspot.sg/2013/02/hacking-facebook-with-oauth2-and-chrome.html) 
- [Appengine Cool Bug](https://proximasec.blogspot.hk/2017/02/a-tale-about-appengines-authentication.html)
- [Slack post message real life experience](https://labs.detectify.com/2017/02/28/hacking-slack-using-postmessage-and-websocket-reconnect-to-steal-your-precious-token/)
- [Bypass redirect_uri](http://nbsriharsha.blogspot.in/2016/04/oauth-20-redirection-bypass-cheat-sheet.html) by nbsriharsha
- [Stealing Facebook Messenger nonce worth 15k](https://stephensclafani.com/2017/03/21/stealing-messenger-com-login-nonces/) 
- [Steal Oculus Nonce and Oauth Flow Bypass](https://medium.com/@lokeshdlk77/bypass-oauth-nonce-and-steal-oculus-response-code-faa9cc8d0d37)

#### Google oauth bypass

- [Bypassing Google Authentication on Periscope's Administration Panel](https://whitton.io/articles/bypassing-google-authentication-on-periscopes-admin-panel/) By Jack Whitton

### CSRF

- [Messenger.com CSRF that show you the steps when you check for CSRF](https://whitton.io/articles/messenger-site-wide-csrf/) by Jack Whitton 
- [Paypal bug bounty: Updating the Paypal.me profile picture without consent (CSRF attack)](https://hethical.io/paypal-bug-bounty-updating-the-paypal-me-profile-picture-without-consent-csrf-attack/) by Florian Courtial
- [Hacking PayPal Accounts with one click (Patched)](http://yasserali.com/hacking-paypal-accounts-with-one-click/) by Yasser Ali
- [Add tweet to collection CSRF](https://hackerone.com/reports/100820) by vijay kumar
- [Facebookmarketingdevelopers.com: Proxies, CSRF Quandry and API Fun](http://philippeharewood.com/facebookmarketingdevelopers-com-proxies-csrf-quandry-and-api-fun/) by phwd
- [How i Hacked your Beats account ? Apple Bug Bounty](https://aadityapurani.com/2016/07/20/how-i-hacked-your-beats-account-apple-bug-bounty/) by @aaditya_purani
- [FORM POST JSON: JSON CSRF on POST Heartbeats API](https://hackerone.com/reports/245346) by Dr.Jones
- [Hacking Facebook accounts using CSRF in Oculus-Facebook integration](https://www.josipfranjkovic.com/blog/hacking-facebook-oculus-integration-csrf)


### Remote Code Execution
- [JDWP Remote Code Execution in PayPal](https://www.vulnerability-lab.com/get_content.php?id=1474) by Milan A Solanki
- [XXE in OpenID: one bug to rule them all, or how I found a Remote Code Execution flaw affecting Facebook's servers](http://www.ubercomp.com/posts/2014-01-16_facebook_remote_code_execution) by Reginaldo Silva
- [How I Hacked Facebook, and Found Someone's Backdoor Script](http://devco.re/blog/2016/04/21/how-I-hacked-facebook-and-found-someones-backdoor-script-eng-ver/) by Orange Tsai
- [How I Chained 4 vulnerabilities on GitHub Enterprise, From SSRF Execution Chain to RCE!](http://blog.orange.tw/2017/07/how-i-chained-4-vulnerabilities-on.html) by Orange Tsai
- [uber.com may RCE by Flask Jinja2 Template Injection](https://hackerone.com/reports/125980) by Orange Tsai
- [Yahoo Bug Bounty - *.login.yahoo.com Remote Code Execution](http://blog.orange.tw/2013/11/yahoo-bug-bounty-part-2-loginyahoocom.html) by Orange Tsai (Sorry its in Chinese Only)
- [How we broke PHP, hacked Pornhub and earned $20,000](https://www.evonide.com/how-we-broke-php-hacked-pornhub-and-earned-20000-dollar/) by Ruslan Habalov
  - *Alert*, God-like Write-up, make sure you know what is ROP before clicking, which I don't =(
- [RCE deal to tricky file upload](https://www.secgeek.net/bookfresh-vulnerability/) by secgeek
- [WordPress SOME bug in plupload.flash.swf leading to RCE in Automatic](https://hackerone.com/reports/134738) by Cure53 (cure53)
- [Read-Only user can execute arbitraty shell commands on AirOS](https://hackerone.com/reports/128750) by 93c08539 (93c08539)
- [Remote Code Execution by impage upload!](https://hackerone.com/reports/158148) by Raz0r (ru_raz0r)
- [Popping a shell on the Oculus developer portal](https://bitquark.co.uk/blog/2014/08/31/popping_a_shell_on_the_oculus_developer_portal) by Bitquark
- [Crazy! PornHub RCE AGAIN!!! How I hacked Pornhub for fun and profit - 10,000$](https://5haked.blogspot.sg/) by 5haked
- [PayPal Node.js code injection (RCE)](http://artsploit.blogspot.hk/2016/08/pprce2.html) by Michael Stepankin
- [eBay PHP Parameter Injection lead to RCE](http://secalert.net/#ebay-rce-ccs)
- [Yahoo Acqusition RCE](https://seanmelia.files.wordpress.com/2016/02/yahoo-remote-code-execution-cms1.pdf)
- [Command Injection Vulnerability in Hostinger](http://elladodelnovato.blogspot.hk/2017/02/command-injection-vulnerability-in.html?spref=tw&m=1) by @alberto__segura
- [RCE in Airbnb by Ruby Injection](http://buer.haus/2017/03/13/airbnb-ruby-on-rails-string-interpolation-led-to-remote-code-execution/) by buerRCE
- [RCE in Imgur by Command Line](https://hackerone.com/reports/212696)
- [RCE in git.imgur.com by abusing out dated software](https://hackerone.com/reports/206227) by Orange Tsai
- [RCE in Disclosure](https://hackerone.com/reports/213558)
- [Remote Code Execution by struct2 Yahoo Server](https://medium.com/@th3g3nt3l/how-i-got-5500-from-yahoo-for-rce-92fffb7145e6)
- [Command Injection in Yahoo Acquisition](http://samcurry.net/how-i-couldve-taken-over-the-production-server-of-a-yahoo-acquisition-through-command-injection/)
- [$50k RCE in JetBrains IDE](http://blog.saynotolinux.com/blog/2016/08/15/jetbrains-ide-remote-code-execution-and-local-file-disclosure-vulnerability-analysis/)
- [Telekom.de Remote Command Execution!](http://www.sec-down.com/wordpress/?p=581) by Ebrahim Hegazy
- [Magento Remote Code Execution Vulnerability!](http://www.sec-down.com/wordpress/?p=578) by Ebrahim Hegazy
- [Yahoo! Remote Command Execution Vulnerability](http://www.sec-down.com/wordpress/?p=87) by Ebrahim Hegazy


####  Deserialization
  - [Java Deserialization in manager.paypal.com](http://artsploit.blogspot.hk/2016/01/paypal-rce.html) by Michael Stepankin
  - [Instagram's Million Dollar Bug](http://www.exfiltrated.com/research-Instagram-RCE.php) by Wesley Wineberg 
  - [(Ruby Cookie Deserialization RCE on facebooksearch.algolia.com](https://hackerone.com/reports/134321) by Michiel Prins (michiel)
  - [Java deserialization](https://seanmelia.wordpress.com/2016/07/22/exploiting-java-deserialization-via-jboss/) by meals

####  Image Tragick
  - [Exploiting ImageMagick to get RCE on Polyvore (Yahoo Acquisition)](http://nahamsec.com/exploiting-imagemagick-on-yahoo/) by NaHamSec
  - [Exploting ImageMagick to get RCE on HackerOne](https://hackerone.com/reports/135072) by c666a323be94d57
  - [Trello bug bounty: Access server's files using ImageTragick](https://hethical.io/trello-bug-bounty-access-servers-files-using-imagetragick/) by Florian Courtial 
  - [40k fb rce](4lemon.ru/2017-01-17_facebook_imagetragick_remote_code_execution.html)
  - [Yahoo Bleed 1](https://scarybeastsecurity.blogspot.hk/2017/05/bleed-continues-18-byte-file-14k-bounty.html)
  - [Yahoo Bleed 2](https://scarybeastsecurity.blogspot.hk/2017/05/bleed-more-powerful-dumping-yahoo.html)

### Direct Object Reference (IDOR)
- [Trello bug bounty: The websocket receives data when a public company creates a team visible board](https://hethical.io/trello-bug-bounty-the-websocket-receives-data-when-a-public-company-creates-a-team-visible-board/) by Florian Courtial 
- [Trello bug bounty: Payments informations are sent to the webhook when a team changes its visibility](https://hethical.io/trello-bug-bounty-payments-informations-are-sent-to-the-webhook-when-a-team-changes-its-visibility/) by Florian Courtial
- [Change any user's password in Uber](https://hackerone.com/reports/143717) by mongo
- [Vulnerability in Youtube allowed moving comments from any video to another](https://www.secgeek.net/youtube-vulnerability/) by secgeek
  - It's *Google* Vulnerability, so it's worth reading, as generally it is more difficult to find Google vulnerability
- [Twitter Vulnerability Could 
Credit Cards from Any Twitter Account](https://www.secgeek.net/twitter-vulnerability/) by secgeek
- [One Vulnerability allowed deleting comments of any user in all Yahoo sites](https://www.secgeek.net/yahoo-comments-vulnerability/) by secgeek
- [Microsoft-careers.com Remote Password Reset](http://yasserali.com/microsoft-careers-com-remote-password-reset/) by Yaaser Ali
- [How I could change your eBay password](http://yasserali.com/how-i-could-change-your-ebay-password/) by Yaaser Ali
- [Duo Security Researchers Uncover Bypass of PayPal’s Two-Factor Authentication](https://duo.com/blog/duo-security-researchers-uncover-bypass-of-paypal-s-two-factor-authentication) by Duo Labs
- [How I got access to millions of [redacted] accounts](https://bitquark.co.uk/blog/2016/02/09/how_i_got_access_to_millions_of_redacted_accounts)
- [All Vimeo Private videos disclosure via Authorization Bypass with Excellent Technical Description](https://hackerone.com/reports/137502) by Enguerran Gillier (opnsec)
- [Urgent: attacker can access every data source on Bime](https://hackerone.com/reports/149907) by Jobert Abma (jobert)
- [Downloading password protected / restricted videos on Vimeo](https://hackerone.com/reports/145467) by Gazza (gazza)
- [Get organization info base on uuid in Uber](https://hackerone.com/reports/151465) by Severus (severus)
- [How I Exposed your Primary Facebook Email Address (Bug worth $4500)](http://roy-castillo.blogspot.hk/2013/07/how-i-exposed-your-primary-facebook.html) by Roy Castillo
- [DOB disclosed using “Facebook Graph API Reverse Engineering”](https://medium.com/@rajsek/my-3rd-facebook-bounty-hat-trick-chennai-tcs-er-name-listed-in-facebook-hall-of-fame-47f57f2a4f71#.9gbtbv42q) by Raja Sekar Durairaj
- [Change the description of a video without publish_actions permission in Facebook](http://philippeharewood.com/change-the-description-of-a-video-without-publish_actions-permission/) by phwd
- [Response To Request Injection (RTRI)](https://www.bugbountyhq.com/front/latestnews/dWRWR0thQ2ZWOFN5cTE1cXQrSFZmUT09/) by ?, be honest, thanks to this article, I have found quite a few bugs because of using his method, respect to the author!
- [Leak of all project names and all user names , even across applications on Harvest](https://hackerone.com/reports/152696) by Edgar Boda-Majer (eboda)
- [Changing paymentProfileUuid when booking a trip allows free rides at Uber](https://hackerone.com/reports/162809) by Matthew Temmy (temmyscript)
- [View private tweet](https://hackerone.com/reports/174721)
- ~~[Hacking Facebook’s Legacy API, Part 1: Making Calls on Behalf of Any User](http://stephensclafani.com/2014/07/08/hacking-facebooks-legacy-api-part-1-making-calls-on-behalf-of-any-user/) by Stephen Sclafani~~
- ~~[Hacking Facebook’s Legacy API, Part 2: Stealing User Sessions](http://stephensclafani.com/2014/07/29/hacking-facebooks-legacy-api-part-2-stealing-user-sessions/) by Stephen Sclafani~~
- [Delete FB Video](https://danmelamed.blogspot.hk/2017/01/facebook-vulnerability-delete-any-video.html)
- [Delete FB Video](https://pranavhivarekar.in/2016/06/23/facebooks-bug-delete-any-video-from-facebook/)
- [Viewing private Airbnb Messages](http://buer.haus/2017/03/31/airbnb-web-to-app-phone-notification-idor-to-view-everyones-airbnb-messages/) 
- [IDOR tweet as any user](http://kedrisec.com/twitter-publish-by-any-user/) by kedrisec
- [Mass Assignment, Response to Request Injection, Admin Escalation](https://seanmelia.wordpress.com/2017/06/01/privilege-escalation-in-a-django-application/) by sean
- [Getting any Facebook user's friend list and partial payment card details](https://www.josipfranjkovic.com/blog/facebook-friendlist-paymentcard-leak)
- [Manipulation of ETH balance](https://www.vicompany.nl/magazine/from-christmas-present-in-the-blockchain-to-massive-bug-bounty)


### XXE
- [How we got read access on Google’s production servers](https://blog.detectify.com/2014/04/11/how-we-got-read-access-on-googles-production-servers/) by  detectify
- [Blind OOB XXE At UBER 26+ Domains Hacked](http://nerdint.blogspot.hk/2016/08/blind-oob-xxe-at-uber-26-domains-hacked.html) by Raghav Bisht
- [XXE through SAML](https://seanmelia.files.wordpress.com/2016/01/out-of-band-xml-external-entity-injection-via-saml-redacted.pdf)
- [XXE in Uber to read local files](https://httpsonly.blogspot.hk/2017/01/0day-writeup-xxe-in-ubercom.html)

### Unrestricted File Upload
- [File Upload XSS in image uploading of App in mopub](https://hackerone.com/reports/97672) by vijay kumar 
- [RCE deal to tricky file upload](https://www.secgeek.net/bookfresh-vulnerability/) by secgeek
- [File Upload XSS in image uploading of App in mopub in Twitter](https://hackerone.com/reports/97672) by vijay kumar (vijay_kumar1110)

### Server Side Request Forgery (SSRF)
- [ESEA Server-Side Request Forgery and Querying AWS Meta Data](http://buer.haus/2016/04/18/esea-server-side-request-forgery-and-querying-aws-meta-data/) by Brett Buerhaus
- [SSRF to pivot internal network](https://seanmelia.files.wordpress.com/2016/07/ssrf-to-pivot-internal-networks.pdf)
- [SSRF to LFI](https://seanmelia.wordpress.com/2015/12/23/various-server-side-request-forgery-issues/)
- [SSRF to query google internal server](https://www.rcesecurity.com/2017/03/ok-google-give-me-all-your-internal-dns-information/)
- [SSRF by using third party Open redirect](https://buer.haus/2017/03/09/airbnb-chaining-third-party-open-redirect-into-server-side-request-forgery-ssrf-via-liveperson-chat/) by Brett BUERHAUS
- [SSRF tips from BugBountyHQ of Images](https://twitter.com/BugBountyHQ/status/868242771617792000)
- [SSRF to RCE](http://www.kernelpicnic.net/2017/05/29/Pivoting-from-blind-SSRF-to-RCE-with-Hashicorp-Consul.html)
- [XXE at Twitter](https://hackerone.com/reports/248668)
- [Blog post: Cracking the Lens: Targeting HTTP’s Hidden Attack-Surface ](http://blog.portswigger.net/2017/07/cracking-lens-targeting-https-hidden.html)
- [Plotly AWS Metadata SSRF (and a stored XSS)](https://ysx.me.uk/a-pair-of-plotly-bugs-stored-xss-and-aws-metadata-ssrf/)

### Race Condition

- [Race conditions on Facebook, DigitalOcean and others (fixed)](http://josipfranjkovic.blogspot.hk/2015/04/race-conditions-on-facebook.html) by Josip Franjković
- [Race Conditions in Popular reports feature in HackerOne](https://hackerone.com/reports/146845) by Fábio Pires (shmoo)
- [Hacking Starbuck for unlimited money](https://sakurity.com/blog/2015/05/21/starbucks.html) by Egor Homakov

### Business Logic Flaw
- [How I Could Steal Money from Instagram, Google and Microsoft](https://www.arneswinnen.net/2016/07/how-i-could-steal-money-from-instagram-google-and-microsoft/) by Arne Swinnen
- [Facebook - bypass ads account's roles vulnerability 2015](http://blog.darabi.me/2015/03/facebook-bypass-ads-account-roles.html) by POUYA DARABI
- [Uber Eat for Free](https://t.co/MCOM7j2dWX) by 

### Authentication Bypass
- [OneLogin authentication bypass on WordPress sites via XMLRPC in Uber](https://hackerone.com/reports/138869) by Jouko Pynnönen (jouko)
- [2FA PayPal Bypass](https://henryhoggard.co.uk/blog/Paypal-2FA-Bypass) by henryhoggard
- [SAML Bug in Github worth 15000](http://www.economyofmechanism.com/github-saml.html)  
- [Authentication bypass on Airbnb via OAuth tokens theft](https://www.arneswinnen.net/2017/06/authentication-bypass-on-airbnb-via-oauth-tokens-theft/)
- [Administrative Panel Access](http://c0rni3sm.blogspot.hk/2017/08/accidentally-typo-to-bypass.html?m=1) by c0rni3sm
- [Flickr Oauth Misconfiguration](https://mishresec.wordpress.com/2017/10/12/yahoo-bug-bounty-exploiting-oauth-misconfiguration-to-takeover-flickr-accounts/) by mishre
- [Slack SAML authentication bypass](http://blog.intothesymmetry.com/2017/10/slack-saml-authentication-bypass.html) by Antonio Sanso
- [Shopify admin authentication bypass using partners.shopify.com](https://hackerone.com/reports/270981) by uzsunny

### HTTP Header Injection
- [Twitter Overflow Trilogy in Twitter](https://blog.innerht.ml/overflow-trilogy/) by filedescriptor
- [Twitter CRLF](https://blog.innerht.ml/twitter-crlf-injection/) by filedescriptor
- [Adblock Plus and (a little) more in Google](https://adblockplus.org/blog/finding-security-issues-in-a-website-or-how-to-get-paid-by-google)
- [$10k host header](https://sites.google.com/site/testsitehacking/10k-host-header) by Ezequiel Pereira

### Subdomain Takeover

- [Hijacking tons of Instapage expired users Domains & Subdomains](http://www.geekboy.ninja/blog/hijacking-tons-of-instapage-expired-users-domains-subdomains/) by geekboy
- [Reading Emails in Uber Subdomains](https://hackerone.com/reports/156536)
- [Slack Bug Journey](http://secalert.net/slack-security-bug-bounty.html) - by David Vieira-Kurz
- [Subdomain takeover and chain it to perform authentication bypass](https://www.arneswinnen.net/2017/06/authentication-bypass-on-ubers-sso-via-subdomain-takeover/) by Arne Swinnen
- [Hacker.One Subdomain Takeover](https://hackerone.com/reports/159156) - by geekboy

## XSSI

- [Plain Text Reading by XSSI](http://balpha.de/2013/02/plain-text-considered-harmful-a-cross-domain-exploit/)
- [JSON hijacking](http://blog.portswigger.net/2016/11/json-hijacking-for-modern-web.html)
- [OWASP XSSI](https://www.owasp.org/images/f/f3/Your_Script_in_My_Page_What_Could_Possibly_Go_Wrong_-_Sebastian_Lekies%2BBen_Stock.pdf)
- [Japan Identifier based XSSI attacks](http://www.mbsd.jp/Whitepaper/xssi.pdf)
- [JSON Hijack Slide](https://www.owasp.org/images/6/6a/OWASPLondon20161124_JSON_Hijacking_Gareth_Heyes.pdf)

## Email Related

- [This domain is my domain - G Suite A record vulnerability](http://blog.pentestnepal.tech/post/156959105292/this-domain-is-my-domain-g-suite-a-record)
- [I got emails - G Suite Vulnerability](http://blog.pentestnepal.tech/post/156707088037/i-got-emails-g-suite-vulnerability)
- [How I snooped into your private Slack messages [Slack Bug bounty worth $2,500]](http://blog.pentestnepal.tech/post/150381068912/how-i-snooped-into-your-private-slack-messages)
- [Reading Uber’s Internal Emails [Uber Bug Bounty report worth $10,000]](http://blog.pentestnepal.tech/post/149985438982/reading-ubers-internal-emails-uber-bug-bounty)
- [Slack Yammer Takeover by using TicketTrick](https://medium.com/@intideceukelaire/how-i-hacked-hundreds-of-companies-through-their-helpdesk-b7680ddc2d4c) by Inti De Ceukelaire
- [How I could have mass uploaded from every Flickr account!](https://ret2got.wordpress.com/2017/10/05/how-i-could-have-mass-uploaded-from-every-flickr-account/)

## Money Stealing

- [Round error issue -> produce money for free in Bitcoin Site](https://hackerone.com/reports/176461) by 4lemon

## 2017 Local File Inclusion

- [Disclosure Local File Inclusion by Symlink](https://hackerone.com/reports/213558)
- [Facebook Symlink Local File Inclusion](http://josipfranjkovic.blogspot.hk/2014/12/reading-local-files-from-facebooks.html)
- [Gitlab Symlink Local File Inclusion](https://hackerone.com/reports/158330)
- [Gitlab Symlink Local File Inclusion Part II](https://hackerone.com/reports/178152)
- [Multiple Company LFI](http://panchocosil.blogspot.sg/2017/05/one-cloud-based-local-file-inclusion.html)
- [LFI by video conversion, excited about this trick!](https://hackerone.com/reports/226756)

## Miscellaneous

- [SAML Pen Test Good Paper](http://research.aurainfosec.io/bypassing-saml20-SSO/)
- [A list of FB writeup collected by phwd](https://www.facebook.com/notes/phwd/facebook-bug-bounties/707217202701640) by phwd
- [NoSQL Injection](http://blog.websecurify.com/2014/08/hacking-nodejs-and-mongodb.html) by websecurify
- [CORS in action](http://www.geekboy.ninja/blog/exploiting-misconfigured-cors-cross-origin-resource-sharing/)
- [CORS in Fb messenger](http://www.cynet.com/blog-facebook-originull/)
- [Web App Methodologies](https://blog.zsec.uk/ltr101-method-to-madness/)
- [XXE Cheatsheet](https://www.silentrobots.com/blog/2015/12/14/xe-cheatsheet-update/)
- [The road to hell is paved with SAML Assertions, Microsoft Vulnerability](http://www.economyofmechanism.com/office365-authbypass.html#office365-authbypass)
- [Study this if you like to learn Mongo SQL Injection](https://cirw.in/blog/hash-injection) by cirw
- [Mongo DB Injection again](http://blog.websecurify.com/2014/08/hacking-nodejs-and-mongodb.html) by websecrify
- [w3af speech about modern vulnerability](https://www.youtube.com/watch?v=GNU0_Uzyvl0) by w3af
- [Web cache attack that lead to account takeover](http://omergil.blogspot.co.il/2017/02/web-cache-deception-attack.html)
- [A talk to teach you how to use SAML Raider](https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/somorovsky)
- [XSS Checklist when you have no idea how to exploit the bug](http://d3adend.org/xss/ghettoBypass)
- [CTF write up, Great for Bug Bounty](https://ctftime.org/writeups?tags=web200&hidden-tags=web%2cweb100%2cweb200)
- [It turns out every site uses jquery mobile with Open Redirect is vulnerable to XSS](http://sirdarckcat.blogspot.com/2017/02/unpatched-0day-jquery-mobile-xss.html) by sirdarckcat
- [Bypass CSP by using google-analytics](https://hackerone.com/reports/199779)
- [Payment Issue with Paypal](https://hackerone.com/reports/219215)
- [Browser Exploitation in Chinese](http://paper.seebug.org/)
- [XSS bypass filter](https://t.co/0Kpzo52ycb)
- [Markup Impropose Sanitization](https://github.com/ChALkeR/notes/blob/master/Improper-markup-sanitization.md)
- [Breaking XSS mitigations via Script Gadget](https://www.blackhat.com/docs/us-17/thursday/us-17-Lekies-Dont-Trust-The-DOM-Bypassing-XSS-Mitigations-Via-Script-Gadgets.pdf)
- [X41 Browser Security White Paper](https://browser-security.x41-dsec.de/X41-Browser-Security-White-Paper.pdf)
- [Bug Bounty Cheatsheets](https://github.com/EdOverflow/bugbounty-cheatsheet) By EdOverflow
- [Messing with the Google Buganizer System for $15,600 in Bounties](https://medium.freecodecamp.org/messing-with-the-google-buganizer-system-for-15-600-in-bounties-58f86cc9f9a5)
- [Electron Security White Paper](https://www.blackhat.com/docs/us-17/thursday/us-17-Carettoni-Electronegativity-A-Study-Of-Electron-Security-wp.pdf)
- [Twitter's Vine Source code dump - $10080](https://avicoder.me/2016/07/22/Twitter-Vine-Source-code-dump/)
- [SAML Bible](https://blog.netspi.com/attacking-sso-common-saml-vulnerabilities-ways-find/)
- [Bypassing Google’s authentication to access their Internal Admin panels — Vishnu Prasad P G](https://medium.com/bugbountywriteup/bypassing-googles-fix-to-access-their-internal-admin-panels-12acd3d821e3)
- [Smart Contract Vulnerabilities](http://www.dasp.co/)
