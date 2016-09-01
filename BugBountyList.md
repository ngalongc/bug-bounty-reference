#Bug Bounty Reference
A list of bug bounty write-up that is categorized by the bug nature, this is inspired by https://github.com/djadmin/awesome-bug-bounty

#Introduction
I have reading for Bug Bounty write-ups for a few months, I found it extremely useful to read relevant write-up when I found a certain type of vulnerability. Let say you found a RPO (Relativce Path Overwrite) in a website, but you have no idea how should you exploit that, then the perfect place to go would be http://blog.innerht.ml/rpo-gadgets/

My intention is to make a full and complete list of common vulnerability that are publicly disclosed bug bounty write-up, and let Bug Bounty Hunter to use this page as a reference when they want to gain some insight for a particular kind of vulnerability during Bug Hunting, feel free to submit pull request. Okay, enough for chit-chatting, let's get started. 


Cross-Site Scripting (XSS) 0 Relative Path Overwrite (RPO)
Brute Force 
SQL Injection (SQLi)
External XML Entity Attack (XXE)
Remote Code Execution (RCE) - Java Deserialization, Image Tragick, BufferOverflow
Cross-Site Request Forgery (CSRF)
Insecure Direct Object Reference (IDOR) - User Information Disclosure, Unauthorized Action
Oauth Bypass Redirect - Google Oauth 
Server Side Request Forgery (SSRF)
Unrestricted File Upload
Business Logic Flaw

Cross-Site Scripting (XSS)

RPO that lead to information leakage in Google by filedescriptor
God-like XSS, Log-in, Log-out, Log-in in Uber by Jack Whitton https://whitton.io/articles/uber-turning-self-xss-into-good-xss/
Three Stored XSS in Facebook by Nirgoldshlager http://www.breaksec.com/?p=6129
Using a Braun Shaver to Bypass XSS Audit and WAF by Frans Rosen, Detectify by Frans Rosen  https://blog.bugcrowd.com/guest-blog-using-a-braun-shaver-to-bypass-xss-audit-and-waf-by-frans-rosen-detectify
An XSS on Facebook via PNGs & Wonky Content Types by Jack Whitton, he is able to make stored XSS from a irrelevant domain to main facebook domain https://whitton.io/articles/xss-on-facebook-via-png-content-types/
Stored XSS in *.ebay.com by Jack Whitton https://whitton.io/archive/persistent-xss-on-myworld-ebay-com/

Stealing Access Token
Facebook Access Token Stolen by Jack Whitton - https://whitton.io/articles/stealing-facebook-access-tokens-with-a-double-submit/
Obtaining Login Tokens for an Outlook, Office or Azure Account by Jack Whitton https://whitton.io/articles/obtaining-tokens-outlook-office-azure-account/ 

CSRF
Messenger.com CSRF that show you the steps when you check for CSRF by Jack Whitton https://whitton.io/articles/messenger-site-wide-csrf/ 

Oauth Redirect Bypass - 
Bypassing Google Authentication on Periscope's Administration Panel By Jack Whitton
https://whitton.io/articles/bypassing-google-authentication-on-periscopes-admin-panel/

Business Logic Flaw
