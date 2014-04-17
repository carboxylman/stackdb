## This script can be used to send web requests to webserver. 
## Network topology : 1 host and 1 webserver connected with a router so that they are on different subnets. The host can IP's in the range 165.98.3.[1-255].
##                    The webserver has IP 10.1.4.2.
##  This scripts is based on the assumptions that darkleech only injects iframes when :
##  1.  the host and the server are on different network.
##  2.  The host shoud have public ip (private or internal IP's not allowed)
##  3.  All webreuests comming without a referrer are blocked. Referrer needs to be a seach engine.
##  4.  Only the second request from a particular source IP is injected with a iframe
##  5.  Source IP's cannot be reused because once darkleech has serviced a source IP it is blacklisted.
## designed based on the information provided here: http://blog.unmaskparasites.com/2012/09/10/malicious-apache-module-injects-iframes/


#!/usr/local/bin/python2.7
import requests
import random
import os
import time
import  codecs


def make_request():
    url = [0]*25
    url[0] = "http://node1/lawfirm/about.html"
    url[1] = "http://node1/lawfirm/lawyers.html"
    url[2] = "http://node1/lawfirm/practices.html"
    url[3] = "http://node1/lawfirm/contact.html"
    url[4] = "http://node1/lawfirm/index.html"
    url[5] = "http://node1/lawfirm/news.html"
    url[6] = "http://node1/lawfirm/singlepost.html"
    url[7] = "http://node1/lawfirm/post.html"
    url[8] = "http://node1/beachresort/about.html"
    url[9] = "http://node1/beachresort/contact.html"
    url[10] = "http://node1/beachresort/dives.html"
    url[11] = "http://node1/beachresort/news.html"
    url[12] = "http://node1/beachresort/foods.html"
    url[13] = "http://node1/beachresort/index.html"
    url[14] = "http://node1/beachresort/rooms.html"
    url[15] = "http://node1/hairstylesalon/about.html"
    url[16] = "http://node1/hairstylesalon/hairstyle.html"
    url[17] = "http://node1/hairstylesalon/news.html"
    url[18] = "http://node1/hairstylesalon/contact.html"
    url[19] = "http://node1/hairstylesalon/index.html"
    url[20] = "http://node1/wood/about.html"
    url[21] = "http://node1/wood/contact.html"
    url[22] = "http://node1/wood/blog.html"
    url[23] = "http://node1/wood/gallery.html"
    url[24] = "http://node1/wood/index.html"

    count = 0
    prev_page_no = 0
    while(1):
	count = (count ) % 3
	page_no = random.randint(0,24)
	random_ip = "165.98.3." + str(random.randint(5,250))
	name = str(time.time()) + ".txt"
	if count == 0 :
	    os.system("sudo ifconfig eth4 " + str(random_ip) + " netmask 255.255.255.0 up")
	    print "set ip"
	    os.system("sudo route add -net 10.0.0.0 netmask 255.0.0.0 gw 165.98.3.3 dev eth4")
	    print "set route"
	    count = 0
	    headers = {'Referer: https' : 'https//www.google.com/#q=lawfirms',
	               'User-Agent' : 'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)'}
        else:
	    headers = {'Referer: https' : url[prev_page_no],
		       'User-Agent' : 'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)'}
	r = requests.get(url[page_no], headers = headers)
	prev_page_no = page_no
	with open(name,"wb") as fd:
	    fd.write(str(r.text.encode('utf-8')))
	time.sleep(random.randint(40,100))
	count = count + 1
	

def main():
    make_request()


if __name__ =='__main__':
    main()

