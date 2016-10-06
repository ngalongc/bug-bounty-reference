#Bug Bounty Reference
A list of bug bounty write-up that is categorized by the bug nature, this is inspired by https://github.com/djadmin/awesome-bug-bounty

#Introduction
I have reading for Bug Bounty write-ups for a few months, I found it extremely useful to read relevant write-up when I found a certain type of vulnerability tha I have no idea how to exploit. Let say you found a RPO (Relativce Path Overwrite) in a website, but you have no idea how should you exploit that, then the perfect place to go would be [here](http://blog.innerht.ml/rpo-gadgets/). Or you have found your customer is using oauth mechanism but you have no idea how should we test it, the other perfect place to go would be [here](https://whitton.io/articles/obtaining-tokens-outlook-office-azure-account/)

My intention is to make a full and complete list of common vulnerability that are publicly disclosed bug bounty write-up, and let Bug Bounty Hunter to use this page as a reference when they want to gain some insight for a particular kind of vulnerability during Bug Hunting, feel free to submit pull request. Okay, enough for chit-chatting, let's get started. 


- [Cross-Site Scripting (XSS)](https://github.com/ngalongc/bug-bounty-reference#cross-site-scripting-xss)
- [Brute Force](https://github.com/ngalongc/bug-bounty-reference/blob/master/README.md#brute-force)
- [SQL Injection (SQLi)](https://github.com/ngalongc/bug-bounty-reference#sql-injection)
- [External XML Entity Attack (XXE)](https://github.com/ngalongc/bug-bounty-reference#xxe)
- [Remote Code Execution (RCE)](https://github.com/ngalongc/bug-bounty-reference#remote-code-execution)
  - [Deserialization](https://github.com/ngalongc/bug-bounty-reference#deserialization)
  - [Image Tragick](https://github.com/ngalongc/bug-bounty-reference#image-tragick)
- [Cross-Site Request Forgery (CSRF)](https://github.com/ngalongc/bug-bounty-reference#csrf)
- [Insecure Direct Object Reference (IDOR)](https://github.com/ngalongc/bug-bounty-reference#insecure-direct-object-reference-idor)
- [Stealing Access Token](https://github.com/ngalongc/bug-bounty-reference#stealing-access-token)
  - [Google Oauth Login Bypass](https://github.com/ngalongc/bug-bounty-reference#google-oauth-bypass)
- [Server Side Request Forgery (SSRF)](https://github.com/ngalongc/bug-bounty-reference#server-side-request-forgery-ssrf)
- [Unrestricted File Upload](https://github.com/ngalongc/bug-bounty-reference#unrestricted-file-upload)
- [Race Condition](https://github.com/ngalongc/bug-bounty-reference#race-condition)
- [Business Logic Flaw](https://github.com/ngalongc/bug-bounty-reference#race-condition#business-logic-flaw)
- [Authentication Bypass](https://github.com/ngalongc/bug-bounty-reference#race-condition#business-logic-flaw#authentication-bypass)
- [HTTP Header Injection]

### Cross-Site Scripting (XSS)

- [Sleeping stored Google XSS Awakens a $5000 Bounty](https://blog.it-securityguard.com/bugbounty-sleeping-stored-google-xss-awakens-a-5000-bounty/) by Patrik Fehrenbach
- [RPO that lead to information leakage in Google](http://blog.innerht.ml/rpo-gadgets/) by filedescriptor
- [God-like XSS, Log-in, Log-out, Log-in](https://whitton.io/articles/uber-turning-self-xss-into-good-xss/) in Uber by Jack Whitton 
- [Three Stored XSS in Facebook](http://www.breaksec.com/?p=6129) by Nirgoldshlager 
- [Using a Braun Shaver to Bypass XSS Audit and WAF](https://blog.bugcrowd.com/guest-blog-using-a-braun-shaver-to-bypass-xss-audit-and-waf-by-frans-rosen-detectify) by Frans Rosen  
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


### Brute Force
- [Web Authentication Endpoint Credentials Brute-Force Vulnerability](https://hackerone.com/reports/127844) by Arne Swinnen
- [InstaBrute: Two Ways to Brute-force Instagram Account Credentials](https://www.arneswinnen.net/2016/05/instabrute-two-ways-to-brute-force-instagram-account-credentials/) by Arne Swinnen
- [How I Could Compromise 4% (Locked) Instagram Accounts](https://www.arneswinnen.net/2016/03/how-i-could-compromise-4-locked-instagram-accounts/) by Arne Swinnen
- [Possibility to brute force invite codes in riders.uber.com](https://hackerone.com/reports/125505) by r0t
- [Brute-Forcing invite codes in partners.uber.com](https://hackerone.com/reports/144616) by Efkan Gökbaş (mefkan)
- [How I could have hacked all Facebook accounts](http://www.anandpraka.sh/2016/03/how-i-could-have-hacked-your-facebook.html) by Anand Prakash
- [Facebook Account Take Over by using SMS verification code](http://arunsureshkumar.me/index.php/2016/04/24/facebook-account-take-over/) by Arun Sureshkumar

### SQL Injection
- [SQL injection in Wordpress Plugin Huge IT Video Gallery in Uber](https://hackerone.com/reports/125932) by glc
- [SQL Injection on sctrack.email.uber.com.cn](https://hackerone.com/reports/150156) by Orange Tsai
- [Yahoo – Root Access SQL Injection – tw.yahoo.com](http://buer.haus/2015/01/15/yahoo-root-access-sql-injection-tw-yahoo-com/) by Brett Buerhaus
- [Multiple vulnerabilities in a WordPress plugin at drive.uber.com](https://hackerone.com/reports/135288) by Abood Nour (syndr0me)

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

#### Google oauth bypass
- [Bypassing Google Authentication on Periscope's Administration Panel](https://whitton.io/articles/bypassing-google-authentication-on-periscopes-admin-panel/) By Jack Whitton

### CSRF
- [Messenger.com CSRF that show you the steps when you check for CSRF](https://whitton.io/articles/messenger-site-wide-csrf/) by Jack Whitton 
- [Paypal bug bounty: Updating the Paypal.me profile picture without consent (CSRF attack)](https://hethical.io/paypal-bug-bounty-updating-the-paypal-me-profile-picture-without-consent-csrf-attack/) by Florian Courtial
- [Hacking PayPal Accounts with one click (Patched)](http://yasserali.com/hacking-paypal-accounts-with-one-click/) by Yasser Ali
- [Add tweet to collection CSRF](https://hackerone.com/reports/100820) by vijay kumar
- [Facebookmarketingdevelopers.com: Proxies, CSRF Quandry and API Fun](http://philippeharewood.com/facebookmarketingdevelopers-com-proxies-csrf-quandry-and-api-fun/) by phwd

### Remote Code Execution
- [JDWP Remote Code Execution in PayPal](https://www.vulnerability-lab.com/get_content.php?id=1474) by Milan A Solanki
- [XXE in OpenID: one bug to rule them all, or how I found a Remote Code Execution flaw affecting Facebook's servers](http://www.ubercomp.com/posts/2014-01-16_facebook_remote_code_execution) by Reginaldo Silva
- [How I Hacked Facebook, and Found Someone's Backdoor Script](http://devco.re/blog/2016/04/21/how-I-hacked-facebook-and-found-someones-backdoor-script-eng-ver/) by Orange Tsai
- [uber.com may RCE by Flask Jinja2 Template Injection](https://hackerone.com/reports/125980) by Orage Tsai
- [Yahoo Bug Bounty - *.login.yahoo.com Remote Code Execution](http://blog.orange.tw/2013/11/yahoo-bug-bounty-part-2-loginyahoocom.html) by Orange Tsai (Sorry its in Chinese Only)
- [How we broke PHP, hacked Pornhub and earned $20,000](https://www.evonide.com/how-we-broke-php-hacked-pornhub-and-earned-20000-dollar/) by Ruslan Habalov
  - *Alert*, God-like Write-up, make sure you know what is ROP before clicking, which I don't =(
- [RCE deal to tricky file upload](https://www.secgeek.net/bookfresh-vulnerability/) by secgeek
- [WordPress SOME bug in plupload.flash.swf leading to RCE in Automatic](https://hackerone.com/reports/134738) by Cure53 (cure53)
- [Read-Only user can execute arbitraty shell commands on AirOS](https://hackerone.com/reports/128750) by 93c08539 (93c08539)
- [Remote Code Execution by impage upload!](https://hackerone.com/reports/158148) by Raz0r (ru_raz0r)
- [Popping a shell on the Oculus developer portal](https://bitquark.co.uk/blog/2014/08/31/popping_a_shell_on_the_oculus_developer_portal) by Bitquark
- [Crazy! PornHub RCE AGAIN!!! How I hacked Pornhub for fun and profit - 10,000$](https://5haked.blogspot.sg/) by 5haked

####  Deserialization
  - [Java Deserialization in manager.paypal.com](http://artsploit.blogspot.hk/2016/01/paypal-rce.html) by Michael Stepankin
  - [Instagram's Million Dollar Bug](http://www.exfiltrated.com/research-Instagram-RCE.php) by Wesley Wineberg 
  - [(Ruby Cookie Deserialization RCE on facebooksearch.algolia.com](https://hackerone.com/reports/134321) by Michiel Prins (michiel)

####  Image Tragick
  - [Exploiting ImageMagick to get RCE on Polyvore (Yahoo Acquisition)](http://nahamsec.com/exploiting-imagemagick-on-yahoo/) by NaHamSec
  - [Exploting ImageMagick to get RCE on HackerOne](https://hackerone.com/reports/135072) by c666a323be94d57
  - [Trello bug bounty: Access server's files using ImageTragick](https://hethical.io/trello-bug-bounty-access-servers-files-using-imagetragick/) by Florian Courtial 

### Insecure Direct Object Reference (IDOR)
- [Trello bug bounty: The websocket receives data when a public company creates a team visible board](https://hethical.io/trello-bug-bounty-the-websocket-receives-data-when-a-public-company-creates-a-team-visible-board/) by Florian Courtial 
- [Trello bug bounty: Payments informations are sent to the webhook when a team changes its visibility](https://hethical.io/trello-bug-bounty-payments-informations-are-sent-to-the-webhook-when-a-team-changes-its-visibility/) by Florian Courtial
- [Change any user's password in Uber](https://hackerone.com/reports/143717) by mongo
- [Vulnerability in Youtube allowed moving comments from any video to another](https://www.secgeek.net/youtube-vulnerability/) by secgeek
  - It's *Google* Vulnerability, so it's worth reading, as generally it is more difficult to find Google vulnerability
- [Twitter Vulnerability Could Delete Credit Cards from Any Twitter Account](https://www.secgeek.net/twitter-vulnerability/) by secgeek
- [One Vulnerability allowed deleting comments of any user in all Yahoo sites](https://www.secgeek.net/yahoo-comments-vulnerability/) by secgeek
- [Microsoft-careers.com Remote Password Reset](http://yasserali.com/microsoft-careers-com-remote-password-reset/) by Yaaser Ali
- [How I could change your eBay password](http://yasserali.com/how-i-could-change-your-ebay-password/) by Yaaser Ali
- [Duo Security Researchers Uncover Bypass of PayPal’s Two-Factor Authentication](https://duo.com/blog/duo-security-researchers-uncover-bypass-of-paypal-s-two-factor-authentication) by Duo Labs
- [Hacking Facebook.com/thanks Posting on behalf of your friends!
](http://www.anandpraka.sh/2014/11/hacking-facebookcomthanks-posting-on.html) by Anand Prakash
- [How I got access to millions of [redacted] accounts](https://bitquark.co.uk/blog/2016/02/09/how_i_got_access_to_millions_of_redacted_accounts)
- [All Vimeo Private videos disclosure via Authorization Bypass with Excellent Technical Description](https://hackerone.com/reports/137502) by Enguerran Gillier (opnsec)
- [Urgent: attacker can access every data source on Bime](https://hackerone.com/reports/149907) by Jobert Abma (jobert)
- [Downloading password protected / restricted videos on Vimeo](https://hackerone.com/reports/145467) by Gazza (gazza)
- [Get organization info base on uuid in Uber](https://hackerone.com/reports/151465) by Severus (severus)
- [How I Exposed your Primary Facebook Email Address (Bug worth $4500)](http://roy-castillo.blogspot.hk/2013/07/how-i-exposed-your-primary-facebook.html) by Roy Castillo
- [DOB disclosed using “Facebook Graph API Reverse Engineering”](https://medium.com/@rajsek/my-3rd-facebook-bounty-hat-trick-chennai-tcs-er-name-listed-in-facebook-hall-of-fame-47f57f2a4f71#.9gbtbv42q) by Raja Sekar Durairaj
- [Change the description of a video without publish_actions permission in Facebook](http://philippeharewood.com/change-the-description-of-a-video-without-publish_actions-permission/) by phwd
- [Response To Request Injection (RTRI)](https://www.bugbountyhq.com/front/latestnews/dWRWR0thQ2ZWOFN5cTE1cXQrSFZmUT09/) by ?, be honest, thanks to this article, I have found quite a few bugs because of using his method, respect to the author!


### XXE
- [How we got read access on Google’s production servers](https://blog.detectify.com/2014/04/11/how-we-got-read-access-on-googles-production-servers/) by  detectify
- [Blind OOB XXE At UBER 26+ Domains Hacked](http://nerdint.blogspot.hk/2016/08/blind-oob-xxe-at-uber-26-domains-hacked.html) by Raghav Bisht

### Unrestricted File Upload
- [File Upload XSS in image uploading of App in mopub](https://hackerone.com/reports/97672) by vijay kumar 
- [RCE deal to tricky file upload](https://www.secgeek.net/bookfresh-vulnerability/) by secgeek
- [File Upload XSS in image uploading of App in mopub in Twitter](https://hackerone.com/reports/97672) by vijay kumar (vijay_kumar1110)

### Server Side Request Forgery (SSRF)
- [ESEA Server-Side Request Forgery and Querying AWS Meta Data](http://buer.haus/2016/04/18/esea-server-side-request-forgery-and-querying-aws-meta-data/) by Brett Buerhaus

### Race Condition
- [Race conditions on Facebook, DigitalOcean and others (fixed)](http://josipfranjkovic.blogspot.hk/2015/04/race-conditions-on-facebook.html) by Josip Franjković
- [Race Conditions in Popular reports feature in HackerOne](https://hackerone.com/reports/146845) by Fábio Pires (shmoo)

### Business Logic Flaw
- [Facebook simple technical hack to see the timeline](http://ashishpadelkar.com/index.php/2015/09/23/facebook-simple-technical-bug-worth-7500/) by Ashish Padelkar
- [How I Could Steal Money from Instagram, Google and Microsoft](https://www.arneswinnen.net/2016/07/how-i-could-steal-money-from-instagram-google-and-microsoft/) by Arne Swinnen
- [How I could have removed all your Facebook notes](http://www.anandpraka.sh/2015/12/summary-this-blog-post-is-about.html)
- [Facebook - bypass ads account's roles vulnerability 2015](http://blog.darabi.me/2015/03/facebook-bypass-ads-account-roles.html) by POUYA DARABI

### Authentication Bypass
- [OneLogin authentication bypass on WordPress sites via XMLRPC in Uber](https://hackerone.com/reports/138869) by Jouko Pynnönen (jouko)

### HTTP Header Injection
- [Twitter Overflow Trilogy in Twitter](https://blog.innerht.ml/overflow-trilogy/) by filedescriptor
- [Twitter CRLF](https://blog.innerht.ml/twitter-crlf-injection/) by filedescriptor
- [Adblock Plus and (a little) more in Google](https://adblockplus.org/blog/finding-security-issues-in-a-website-or-how-to-get-paid-by-google)

## Subdomain Takeover
- [Hijacking tons of Instapage expired users Domains & Subdomains](http://www.geekboy.ninja/blog/hijacking-tons-of-instapage-expired-users-domains-subdomains/) by geekboy
- [Reading Emails in Uber Subdomains](https://hackerone.com/reports/156536)
