# cve

A series of scripts that I used to scrape and parse data from two domains:
* [cvedetails.com](https://www.cvedetails.com/): CVE&reg; (["Common Vulnerabilities and Exposures"](https://cve.mitre.org/)) identifies publicly known cybersecurity vulnerabilities. It is a collection of records identified by unique identifiers (year + id number), enumerating security vulnerabilities in widely-distributed software that has become open knowledge.
* [exploit-db.com](https://www.exploit-db.com/): The Exploit Database is a non-profit community project maintained by the *Offensive Security* company. It maintains a CVE-compliant list of public exploits and affected software known for use by [pentesters](https://en.wikipedia.org/wiki/Penetration_test) and researchers.

Python web-facing modules used:
* [requests](https://requests.readthedocs.io/en/master/), [requests-html](https://requests.readthedocs.io/projects/requests-html/en/latest/): a library that <span style="color:#3393FF">intends to make parsing HTML (e.g. scraping the web) as simple and intuitive as possible.</span>
* [bs4](https://www.crummy.com/software/BeautifulSoup/): The codename for the BeautifulSoup-4 library, a go-to for parsing web-page response data as a tree structure based on HTML tags. Particularly useful for webpages that do not make heavy use of dynamically generated content (via javascript, AJAX). The *cvedetails.com* pages are static and thus are easily handled in this manner.
* Selenium ([website](https://www.selenium.dev/), [guide for Python bindings](https://selenium-python.readthedocs.io/), [short docs](https://www.selenium.dev/selenium/docs/api/py/index.html)): as the website states, <span style="color:#3393FF">"Selenium automates browsers. That's it!"</span> When a site makes thorough use of dynamic content, Selenium is one option for handling this. The *exploit-db.com* site is an example.

Features of interest:
* Includes option to concurrently scrape pages using a variable number of threads that draw URLs from a concurrency-safe [queue](https://docs.python.org/3/library/queue.html).
* Provides functionality to provide updates at a specified time interval to the terminal to update on progress.
* If a request for a given URL fails, the scraper examines the [HTTP response status code](https://en.wikipedia.org/wiki/List_of_HTTP_status_codes), and on this basis decides whether it can retry the URL. If not, the page is marked as unsuccessful; if so, a maximum number of retries is imposed, and if the page is attempted and failed this number of times, it is then marked as unsuccessful.
* If the relevant option is enabled, the scraper periodically stores results to disk in the event the scraper shuts down unexpectedly, and it is able to figure out where it left off and resume at that point.
* Adds command-line functionality to specify options for scraping.

Updates to come as I generalize the functionality of these scripts.