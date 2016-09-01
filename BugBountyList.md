#Bug Bounty Reference
A list of bug bounty write-up that is categorized by the bug nature, this is inspired by https://github.com/djadmin/awesome-bug-bounty

#Introduction
I have reading for Bug Bounty write-ups for a few months, I found it extremely useful to read relevant write-up when I found a certain type of vulnerability tha I have no idea how to exploit. Let say you found a RPO (Relativce Path Overwrite) in a website, but you have no idea how should you exploit that, then the perfect place to go would be [here](http://blog.innerht.ml/rpo-gadgets/). Or you have found your customer is using oauth mechanism but you have no idea how should we test it, the other perfect place to go would be [here](https://whitton.io/articles/obtaining-tokens-outlook-office-azure-account/)

My intention is to make a full and complete list of common vulnerability that are publicly disclosed bug bounty write-up, and let Bug Bounty Hunter to use this page as a reference when they want to gain some insight for a particular kind of vulnerability during Bug Hunting, feel free to submit pull request. Okay, enough for chit-chatting, let's get started. 


- Cross-Site Scripting (XSS)
  - Relative Path Overwrite (RPO)
- Brute Force 
- SQL Injection (SQLi)
- External XML Entity Attack (XXE)
- Remote Code Execution (RCE)
  - Java Deserialization
  - Image Tragick
  - BufferOverflow
- Cross-Site Request Forgery (CSRF)
- Insecure Direct Object Reference (IDOR)
  - User Information Disclosure
  - Unauthorized Action
- Oauth Bypass Redirect 
  - Google Oauth 
- Server Side Request Forgery (SSRF)
- Unrestricted File Upload
- Business Logic Flaw

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

### SQL Injection
- [SQL injection in Wordpress Plugin Huge IT Video Gallery in Uber](https://hackerone.com/reports/125932) by glc
- [SQL Injection on sctrack.email.uber.com.cn](https://hackerone.com/reports/150156) by Orange Tsai

### Stealing Access Token
- [Facebook Access Token Stolen](https://whitton.io/articles/stealing-facebook-access-tokens-with-a-double-submit/) by Jack Whitton - 
- [Obtaining Login Tokens for an Outlook, Office or Azure Account](https://whitton.io/articles/obtaining-tokens-outlook-office-azure-account/) by Jack Whitton 
- [Stored XSS in Google Docs (Bug Bounty)](http://hmgmakarovich.blogspot.hk/2015/11/stored-xss-in-google-docs-bug-bounty.html) by Harry M Gertos
- [Bypassing callback_url validation on Digits](https://hackerone.com/reports/108113) by filedescriptor

### CSRF
- [Messenger.com CSRF that show you the steps when you check for CSRF](https://whitton.io/articles/messenger-site-wide-csrf/) by Jack Whitton 
- [Paypal bug bounty: Updating the Paypal.me profile picture without consent (CSRF attack)](https://hethical.io/paypal-bug-bounty-updating-the-paypal-me-profile-picture-without-consent-csrf-attack/) by Florian Courtial
- [Hacking PayPal Accounts with one click (Patched)](http://yasserali.com/hacking-paypal-accounts-with-one-click/) by Yasser Ali
- [Add tweet to collection CSRF](https://hackerone.com/reports/100820) by vijay kumar

### Oauth Redirect Bypass 
- [Bypassing Google Authentication on Periscope's Administration Panel](https://whitton.io/articles/bypassing-google-authentication-on-periscopes-admin-panel/) By Jack Whitton
- [Bypassing Digits web authentication's host validation with HPP](https://hackerone.com/reports/114169) by filedescriptor
- [Obtaining Login Tokens for an Outlook, Office or Azure Account](https://whitton.io/articles/obtaining-tokens-outlook-office-azure-account/) by Jack Whitton

### Remote Code Execution
- [JDWP Remote Code Execution in PayPal](https://www.vulnerability-lab.com/get_content.php?id=1474) by Milan A Solanki
- [XXE in OpenID: one bug to rule them all, or how I found a Remote Code Execution flaw affecting Facebook's servers](http://www.ubercomp.com/posts/2014-01-16_facebook_remote_code_execution) by Reginaldo Silva
- [Instagram's Million Dollar Bug](http://www.exfiltrated.com/research-Instagram-RCE.php) by Wesley Wineberg
- [How I Hacked Facebook, and Found Someone's Backdoor Script](http://devco.re/blog/2016/04/21/how-I-hacked-facebook-and-found-someones-backdoor-script-eng-ver/) by Orange Tsai
- [uber.com may RCE by Flask Jinja2 Template Injection](https://hackerone.com/reports/125980) by Orage Tsai
- [Yahoo Bug Bounty - *.login.yahoo.com Remote Code Execution](http://blog.orange.tw/2013/11/yahoo-bug-bounty-part-2-loginyahoocom.html) by Orange Tsai (Sorry its in Chinese Only)
  -  *Java Deserialization*
    - [Java Deserialization in manager.paypal.com](http://artsploit.blogspot.hk/2016/01/paypal-rce.html) by Michael Stepankin
  -  *Image Tragick*
    - [Exploiting ImageMagick to get RCE on Polyvore (Yahoo Acquisition)](http://nahamsec.com/exploiting-imagemagick-on-yahoo/) by NaHamSec
    - [Exploting ImageMagick to get RCE on HackerOne](https://hackerone.com/reports/135072) by c666a323be94d57
- [How we broke PHP, hacked Pornhub and earned $20,000](https://www.evonide.com/how-we-broke-php-hacked-pornhub-and-earned-20000-dollar/) by Ruslan Habalov
  - *Alert*, God-like Write-up, make sure you know what is ROP before clicking, which I don't =(
  
### Business Logic Flaw
- [Microsoft-careers.com Remote Password Reset](http://yasserali.com/microsoft-careers-com-remote-password-reset/) by Yaaser Ali
- [How I could change your eBay password](http://yasserali.com/how-i-could-change-your-ebay-password/) by Yaaser Ali

### Insecure Direct Object Reference (IDOR)
- [Trello bug bounty: The websocket receives data when a public company creates a team visible board](https://hethical.io/trello-bug-bounty-the-websocket-receives-data-when-a-public-company-creates-a-team-visible-board/) by Florian Courtial 
- [Trello bug bounty: Payments informations are sent to the webhook when a team changes its visibility](https://hethical.io/trello-bug-bounty-payments-informations-are-sent-to-the-webhook-when-a-team-changes-its-visibility/) by Florian Courtial
- [Change any user's password in Uber](https://hackerone.com/reports/143717) by mongo

### XXE
- [How we got read access on Google’s production servers](https://blog.detectify.com/2014/04/11/how-we-got-read-access-on-googles-production-servers/) by  detectify
- [Blind OOB XXE At UBER 26+ Domains Hacked](http://nerdint.blogspot.hk/2016/08/blind-oob-xxe-at-uber-26-domains-hacked.html) by Raghav Bisht

### Unrestricted File Upload
- [File Upload XSS in image uploading of App in mopub](https://hackerone.com/reports/97672) by vijay kumar 
