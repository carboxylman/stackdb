#!/usr/local/bin/python2.7
import requests
import random
import os
import time
import  codecs


def make_request():
    url = [0]*25
    url[0] = "http://10.1.4.10/lawfirm/about.html"
    url[1] = "http://10.1.4.10/lawfirm/lawyers.html"
    url[2] = "http://10.1.4.10/lawfirm/practices.html"
    url[3] = "http://10.1.4.10/lawfirm/contact.html"
    url[4] = "http://10.1.4.10/lawfirm/index.html"
    url[5] = "http://10.1.4.10/lawfirm/news.html"
    url[6] = "http://10.1.4.10/lawfirm/singlepost.html"
    url[7] = "http://10.1.4.10/lawfirm/post.html"
    url[8] = "http://10.1.4.10/beachresort/about.html"
    url[9] = "http://10.1.4.10/beachresort/contact.html"
    url[10] = "http://10.1.4.10/beachresort/dives.html"
    url[11] = "http://10.1.4.10/beachresort/news.html"
    url[12] = "http://10.1.4.10/beachresort/foods.html"
    url[13] = "http://10.1.4.10/beachresort/index.html"
    url[14] = "http://10.1.4.10/beachresort/rooms.html"
    url[15] = "http://10.1.4.10/hairstylesalon/about.html"
    url[16] = "http://10.1.4.10/hairstylesalon/hairstyle.html"
    url[17] = "http://10.1.4.10/hairstylesalon/news.html"
    url[18] = "http://10.1.4.10/hairstylesalon/contact.html"
    url[19] = "http://10.1.4.10/hairstylesalon/index.html"
    url[20] = "http://10.1.4.10/wood/about.html"
    url[21] = "http://10.1.4.10/wood/contact.html"
    url[22] = "http://10.1.4.10/wood/blog.html"
    url[23] = "http://10.1.4.10/wood/gallery.html"
    url[24] = "http://10.1.4.10/wood/index.html"

    #count = 0
    #prev_page_no = 0
    i = 4
    page_no =0
    while(i < 255):
	flag = 0
	print "----------------- sending request-------------------------"
	#count = (count ) % 3
	page_no = random.randint(0,24)
	random_ip = "165.98.3." + str(i) #str(random.randint(5,250))
	name = str(time.time()) + ".txt"
	#if count == 0 :
	os.system("sudo ifconfig eth2 " + str(random_ip) + " netmask 255.255.255.0 up")
	os.system("sudo route add -net 10.0.0.0 netmask 255.0.0.0 gw 165.98.3.3 dev eth2")
	#count = 0
	headers = {'Referer' : 'https://www.google.com/#q=wood_work',
		    #'User-Agent' : 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:24.0) Gecko/20100101 Firefox/24.0'}
		    'User-Agent' : 'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)'}
		    #'User-agent':'Mozilla/5.0 (compatible; MSIE 10.6; Windows NT 6.1; Trident/5.0; InfoPath.2; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR  3.5.30729; .NET CLR 2.0.50727) 3gpp-gba UNTRUSTED/1.0'}
        #else:
	#    headers = {'Referer: https' : url[prev_page_no],
        #	        'User-Agent' : 'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)'}
	r = requests.get(url[0], headers = headers)
	#prev_page_no = page_no
	print "Got response"
	with open(name,"wb") as fd:
	    fd.write(str(r.__dict__.values()))
	    fd.write(str(r.text.encode('utf-8')))
	
	if "iframe" in str(r.__dict__.values()):
	    print "----- iframe detected------"
	    flag = 1;
	if "_PHP_SESSID" in str(r.__dict__.values()):
	    print "---- cookie detected------"
	    flag = 1;
	if flag == 0:
	    print " ----- NO cookie or iframe found -----"
	i = i + 1
	time.sleep(1)
	
def main():
    make_request()


if __name__ =='__main__':
    main()

