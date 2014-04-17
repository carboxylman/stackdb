## This is a simple script used to make darkleech inject iframes into  responces for web request.
##  Requirements:
##  1. Host and webserver should be on different networks.
##  2. Host cannot have private IP's.
##  3. User agent string matter a lot.( looks like windows IE is a favourite  for darkleech) 
##  4. Once a request from a host IP is processed by darkleech, the IP is blacklisted.


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

    i = 4
    page_no =0
    while(1):
	random_ip = "165.98.3." + str(i)
	name = str(time.time()) + ".txt"
	os.system("sudo ifconfig eth2 " + str(random_ip) + " netmask 255.255.255.0 up")
	os.system("sudo route add -net 10.0.0.0 netmask 255.0.0.0 gw 165.98.3.3 dev eth2")
	headers = {'Referer: https' : 'https//www.google.com/#q=lawfirms',
	               'User-Agent' : 'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)'}
		       #'User-Agent' : 'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)'}
	r = requests.get(url[page_no], headers = headers)
	with open(name,"wb") as fd:
	    fd.write(str(r.text.encode('utf-8')))
	i = i + 1
	

def main():
    make_request()


if __name__ =='__main__':
    main()

