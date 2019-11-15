# The easiest way for pushing Nessus scan results into Splunk via Python

**If you manage Nessus Professional and Splunk at your company, you must read this guide to overcoming some barriers encountered towards the vulnerability management process.**

Nessus Professional is a really great tool for performing vulnerability scans, but not friendly when the subject is data export, maybe some of you remember now how difficult it is to work with the CSV file exported from Nessus, it's even harder when the boss needs a quick and detailed vulnerability report. For those who have never had the chance to work with Nessus Professional before, look at the screenshot below:


Certainly, the parse of such a CSV file is not something that you can do easily, huh!?

The good news is that technology exists to make our lives a little bit easy, let's dive in and take the most of it.

# HEC - HTTP Event Collector

To start, the HEC configuration on Splunk's side is required. By the way, what is HEC?

*The HTTP Event Collector (HEC) is a fast and efficient way to send data to Splunk Enterprise and Splunk Cloud. Notably, HEC enables you to send data over HTTP (or HTTPS) directly to Splunk Enterprise or Splunk Cloud from your application. Also, HEC is token-based, so you never need to hard-code your Splunk Enterprise or Splunk Cloud credentials in your app or supporting files.*

As now we have an idea of what HEC it is, let's move on for configuration.
