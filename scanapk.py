import os
import os.path
import sys
import tempfile
import subprocess
import zipfile
import math
import yara


def  filesindir(rootdir):
    files=[]
    for dirpath, dirnames, filenames in os.walk(rootdir):
        for filename in [f for f in filenames]:
#        for filename in [f for f in filenames if f.endswith(".log")]:
            f=os.path.join(dirpath, filename)
            files.append(f)
    return files
    
def rec_unzip(initial_zip,store):
    still_unhandled_zipfiles=True
    current_zip=initial_zip
    dest=store
    while still_unhandled_zipfiles:
        z = zipfile.ZipFile(current_zip)
        z.extractall(dest)
        p = z.namelist()
        for l in p:
            dest="%s/%s.unpack" % (store,l)


def unpack_recursive_zip(__zipfile='', path_from_local=''):
    filepath = path_from_local+__zipfile
    extract_path = filepath.strip('.zip')+'/'
    parent_archive = zipfile.ZipFile(filepath)
    parent_archive.extractall(extract_path)
    namelist = parent_archive.namelist()
    parent_archive.close()
    for name in namelist:
        try:
            #if name[-4:] == '.zip':
            unpack_zip(__zipfile=name, path_from_local=extract_path)
        except:
            print 'failed on', name
            pass
    return extract_path
    
    # you can just call this with filename set to the relative path and file.
    path = unpack_zip(filename)

def unpack(path):
    #### split lib.xzs 

    import mmap
    import os 
    import os.path
    import sys 
    import subprocess
    name=path
    #name=sys.argv[1] # directory name
    name=name+"/assets/lib/"

    lib=name+"/"+"libs.xzs" 
    met=name+"/"+"metadata.txt"


    # 1. unxz lib 
    # 2. parse metadata, line by line unpack

    print lib

    #cmd="cat "+lib+" | xz -d"

    p1 = subprocess.Popen(["cat",lib], stdout=subprocess.PIPE)
    p2 = subprocess.Popen(["xz", "-d"], stdin=p1.stdout, stdout=subprocess.PIPE)
    p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.
    output = p2.communicate()[0]

    bin=open ("out.bin","wb")
    bin.write(output)
    bin.close()

    #l = subprocess.check_output(cmd)

    #print l 

    #l.wait()

    mets = open(met,"r").readlines()

    print mets

    with open("out.bin", "r+b") as f:
        # memory-map the file, size 0 means whole file
        mm = mmap.mmap(f.fileno(), 0)
        start = 0
        for m in mets:
            items = m.split()
            print items
            name=items[0]
            length=int(items[1])
            chksum=items[2]
            bytes=mm[start:start+length]
            start = start+length
            base=os.path.basename(name)
            thedir = os.path.dirname(name)
            try:
                print "making %s" % thedir
                os.makedirs (thedir)
            except:
                pass
                
            r = open(name,"wb")
            r.write(bytes)
            r.close()


def contains(a,b):
    return a.find(b) > -1

thefile = sys.argv[1]

outfile=thefile+".txt"


i=0
for arg in sys.argv:
    
    if arg=="--outfile":
        outfile=sys.argv[i+1]
    i=i+1

    
print "[+] will write output to \n[+] %s" % outfile

if outfile !="-":
    sys.stdout=open(outfile,"w")

store=tempfile.mkdtemp("apk","scanapk")
print "[+] artifacts temporary store at %s" % store
z = zipfile.ZipFile(thefile)
#print z
z.extractall(store)

#unpack_recursive_zip(thefile,store)

p = z.namelist()

show_expanded_devpaths=False
show_expanded_jnimeths=False

sofiles = [ x for x in p if x.endswith(".so")]

certfiles = [ x for x in p if (x.endswith(".DSA") or x.endswith(".RSA"))]

sffiles = [ x for x in p if (x.lower().endswith(".sf"))]

knownv8_versions=["3.26.31.15","3.9.24.29","5.1.281.26", "5.2.361.32"]

dangerous_perms=["android.permission.PROCESS_OUTGOING_CALLS","android.permission.READ_CALENDAR","android.permission.READ_CALL_LOG","android.permission.READ_CONTACTS","android.permission.READ_EXTERNAL_STORAGE","android.permission.READ_PHONE_NUMBERS","android.permission.READ_PHONE_STATE","android.permission.READ_SMS","android.permission.RECEIVE_MMS","android.permission.RECEIVE_SMS","android.permission.RECEIVE_WAP_PUSH","android.permission.RECORD_AUDIO","android.permission.SEND_SMS","android.permission.USE_SIP","android.permission.WRITE_CALENDAR","android.permission.WRITE_CONTACTS","android.permission.WRITE_EXTERNAL_STORAGE","android.permission.WRITE_CALL_LOG","android.permission.WRITE_SMS"]


not3rdparty_perms=["android.permission.ACCESS_CHECKIN_PROPERTIES","android.permission.ACCOUNT_MANAGER","android.permission.BIND_APPWIDGET","android.permission.BROADCAST_PACKAGE_REMOVED","android.permission.BROADCAST_SMS","android.permission.BROADCAST_WAP_PUSH","android.permission.CALL_PRIVILEGED","android.permission.CAPTURE_AUDIO_OUTPUT","android.permission.CAPTURE_SECURE_VIDEO_OUTPUT","android.permission.CAPTURE_VIDEO_OUTPUT","android.permission.CHANGE_COMPONENT_ENABLED_STATE","android.permission.CONTROL_LOCATION_UPDATES","android.permission.DELETE_CACHE_FILES","android.permission.DELETE_PACKAGES","android.permission.DIAGNOSTIC","android.permission.DUMP","android.permission.FACTORY_TEST","android.permission.INSTALL_LOCATION_PROVIDER"]


otherelf=[]
#morezips=[] # no recursion yet, one level zip resolver

moreunpacked=True

while moreunpacked==True:
    otherelf=[]
    moreunpacked=False
    #q=p
    p=filesindir(store)
  
    for l in p:
        if l.endswith("/"):
            continue
        filepath="%s/%s" % (store,l)
        filepath=l #"%s/%s" % (store,l)
        with open(filepath, 'rb') as f:
            head=f.read(4)
            if head[1:]=="ELF":
                otherelf.append(l)
            if head=='PK\x03\x04':
                #print "found potential zip in %s" % (l)
                #morezips.append(l)
                try:
                    z = zipfile.ZipFile(l)
                    
                    newpath=l+".unpacked"
                    if os.path.exists(newpath):
                        #print "%s exists, skipping unpack" % (newpath)
                        continue
                    #print "unpack %s to %s" % (l,newpath)
                    z.extractall(newpath)
                    pp = z.namelist()
                                            
                    moreunpacked=True
                except:
                    pass
        
print "elf files found=%s" % otherelf
#print "morezips=%s" % morezips 


#sys.exit(0)


str=[]
print 

#for theso in sofiles:
for theso in otherelf:
    reltheso=theso.replace(store,"")
    reltheso=reltheso.replace("\\","/")
    r=len(reltheso)
    
    print 
    print "=" * r 
    print reltheso
    print "=" * r 
    #fullso=subprocess.check_output(["strings","%s/%s" % (store,theso)])
    fullso=subprocess.check_output(["strings","%s" % (theso)])
    size=-1
    try:
        #zipinfo = z.getinfo(theso)
        #size=zipinfo.file_size
        size=os.path.getsize(theso)
    except:
        pass
#    sha256=subprocess.check_output(["sha256sum","%s/%s" % (store,theso)]).split()[0][1:]
    sha256=subprocess.check_output(["sha256sum","%s" % (theso)]).split()[0][1:]

    radare2full=subprocess.check_output(["c:\\Program Files (x86)\\Radare2\\radare2.exe","-q","-c", "ij",theso])

    radare2bin=subprocess.check_output(["c:\\Program Files (x86)\\Radare2\\radare2.exe","-q","-c", "iIj",theso])

    p = fullso.split("\n")
    gcc = "Unknown"
    gold = "Unknown"
    
    bbox_version = "Unknown"
    openssl_version = "Unknown"
    libressl_version = "Unknown"
    libjpeg_turbo_version="Unknown"
    libjpeg_version="Unknown"
    libpng_version="Unknown"
    libtiff_version="Unknown"
    zlib_version="Unknown"
    unziplib_version="Unknown"
    curl_version="Unknown"
    sqlite_version="Unknown"
    v8_version="Unknown"
    p7z_version="Unknown"
    openal_version="Unknown"
    dangerous_api=[]
    haslibxml=False
    libxmlVersion="Unknown"
    isjni = False
    v8=False
    v8_string=""
    jnitext=""
    devpaths=[]
    jnimeths=[]
    for l in p:
        l = l.strip()
        if l.startswith("GCC:"):
            gcc = l.strip()
        if l.startswith("gold "):
            gold = l.strip()
        if l == "JNI_OnLoad":
            isjni=True
            jnitext=", JNI_OnLoad"
        
        if l.startswith("Java_") and l.find(" ")==-1:
            isjni=True
            jnimeths.append(l.replace("Java_","").replace("_","."))
        
        
        if l=="strcpy" or l=="strcmp" or l=="strcat" or l=="sprintf" or l=="vsprintf" or l=="gets":
           dangerous_api.append(l)
        
        if contains(l,"OpenSSL") and (contains(l,"0.9.") or contains(l,"1.0.") or contains(l,"1.1.")):
            openssl_version=l[l.find("OpenSSL"):]
        if contains(l,"LibreSSL") and contains(l,"2.") :
            libressl_version=l
        if len(l) > 6 and (l.lower()[0] >= 'a') and (l.lower()[0] <= 'z') and l[1]==":" and (l[2] =="\\" or l[2]=="/"):
            devpaths.append(l)
        if len(l) > 6 and (l.startswith("/Users/") or l.startswith("/home/")) or l.startswith("/cygdrive"):
            devpaths.append(l)
        if contains(l,"var kDefaultBacktraceLength=10"):
            v8=True
            for v8string in knownv8_versions:
                if contains(fullso,v8string):
                    v8_version=v8string

        if contains(l,"Copyright (C) 1991-") and contains(l,"The libjpeg-turbo"):
            libjpeg_turbo_version=l

        if contains(l,"Copyright (C) 1991-2010 Thomas G. Lane, Guido Vollbeding") :
            libjpeg_version="6b"

        if contains(l,"Copyright (C) 2013, Thomas G. Lane, Guido Vollbeding") :
            libjpeg_version="9  13-Jan-2013"

        if contains(l,"LIBTIFF, Version") :
            libtiff_version=l

        if contains(l,"libpng version 1"):
            libpng_version=l

        if contains(l,"7z Decoder") :
            p7z_version=l

        if contains(l,"ALSOFT") :
            openal_version=l

        if contains(l,"CLIENT libcurl") :
            curl_version=l[l.find("libcurl"):]
			
        if contains(l,"BusyBox v"):
            bbox_version=l
			
#        if (contains(l,"deflate") or contains(l,"inflate")) and contains(l,"Copyright 1995-"):
#            print l

        if (contains(l,"deflate") or contains(l,"inflate")) and contains(l,"Copyright 1995-") and (contains(l,"Mark Adler") or contains(l,"Jean-loup Gailly")):
            zlib_version=l.split(" ")[1]

        if contains(l,"unzip 1.01 Copyright 1998-2004 Gilles Vollant"):
            unziplib_version=l
			
        if contains(l,"bbd85d235f7037c6a033a9690534391ffeacecc8"):
            sqlite_version="3.15.2 (bbd85d235f7037c6a033a9690534391ffeacecc8, 2016-11-28)"

        if contains(l,"3d862f207e3adc00f78066799ac5a8c282430a5f"):
            sqlite_version="3.11.0 (3d862f207e3adc00f78066799ac5a8c282430a5f, 2016-02-15)"

        if contains(l,"7dd4968f235d6e1ca9547cda9cf3bd570e1609ef"):
            sqlite_version="3.8.0.2 (7dd4968f235d6e1ca9547cda9cf3bd570e1609ef, 2013-09-03)"

        if contains(l,"979f04392853b8053817a3eea2fc679947b437fd"):
            sqlite_version="3.16.1 (979f04392853b8053817a3eea2fc679947b437fd, 2017-01-03)"
		
        if contains(l,"118a3b35693b134d56ebd780123b7fd6f1497668"):
            sqlite_version="3.7.17 (118a3b35693b134d56ebd780123b7fd6f1497668, 2013-05-20)"
		
        
        
        if contains(l,"Cannot initialize memory for sentinel"):
            haslibxml=True
        
        if contains(l,"208000"):
            libxmlVersion="2.8.0"
        
        if contains(l,"20902"):
            libxmlVersion="2.9.2"
        

        if (len(l)>7):
            str.append((l,theso))
        
        
    #print "%s:" % theso
    
    print "%s, %s%s" % (gcc,gold,  jnitext)
    if v8:
        print "v8=%s" % v8,v8_version
    if openssl_version != "Unknown":
        print "openssl=%s" % openssl_version
    if libressl_version != "Unknown":
        print "libressl=%s" % libressl_version
    if libjpeg_turbo_version != "Unknown":
        print "libjpeg-turbo=%s" % libjpeg_turbo_version
    if libjpeg_version != "Unknown":
        print "libjpeg=%s" % libjpeg_version
    if libtiff_version != "Unknown":
        print "libtiff=%s" % libtiff_version
    if libpng_version != "Unknown":
        print "libpng=%s" % libpng_version
    if zlib_version != "Unknown":
        print "zlib=%s" % zlib_version
    if sqlite_version != "Unknown":
        print "sqlite=%s" % sqlite_version
    if p7z_version!="Unknown":
        print "7z=%s" % p7z_version
    if curl_version!="Unknown":
        print "curl=%s" % curl_version
    if unziplib_version!="Unknown":
        print "unzip=%s" % unziplib_version
    if openal_version!="Unknown":
        print "openal=%s" % openal_version
    if bbox_version!="Unknown":
        print "busybox=%s" % bbox_version
    if haslibxml:
        print "libxml=%s" % libxmlVersion
    if devpaths !=[]:
        anz = int(math.log(len(devpaths)))
        print ("devpath=%s" % (devpaths[0:anz+1]+["..."]) if not show_expanded_devpaths else devpaths )
	
    if jnimeths!=[]:
        anz = int(math.log(len(jnimeths)))
        print ("JNI methods=%s" % (jnimeths[0:anz+1]+["..."]) if not show_expanded_jnimeths else jnimeths )

    if dangerous_api!=[]:
        print ("Suspicious calls=%s" % dangerous_api)

        
    print "SHA256=%s" % sha256
    print "Size=%s" % size
    print "Header (r2) full=%s" % radare2full
    print "Header (r2) bin=%s" % radare2bin
    print "\n"


txtfile = thefile.replace("apk","txt")
f = open(txtfile,"w")
for (p,x) in str:
    f.write("%s:%s\n" % (p,x))
f.close()

    
if sffiles!=[]:
    r = open("%s/%s" % (store,sffiles[0]),"rb").read()
    l = r.find("-Digest-Manifest:")
    k = r.rfind("\n",0,l)
    signhash=r[k+1:l]
    print "============================="
    print "Signhash: %s" % signhash
#print l,k
    print "============================="
    cert=subprocess.check_output(["openssl","pkcs7","-inform","DER","-print_certs","-in","%s/%s" % (store,certfiles[0])])
    print 
    print "==============================="
    print cert
    print "==============================="
    newcert=cert[cert.find("-----BEGIN"):]
    p1 = subprocess.Popen(["echo",newcert], stdout=subprocess.PIPE)
    p2 = subprocess.Popen(["openssl", "x509","-noout","-dates"], stdin=p1.stdout, stdout=subprocess.PIPE)
    p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.
    output = p2.communicate()[0].strip()
    print output
    print "==============================="
    print 


if thefile.lower().endswith("apk"):
    perms=subprocess.check_output(["d:\\android\\SDK\\build-tools\\25.0.3\\aapt.exe","d","permissions",thefile]).split("\n")
    #print perms
    perms = [ x.split("'")[1] for x in perms if contains(x,"uses-permission:")]
    #print perms
    for l in perms:
        lprint = l.replace("android.permission.","a.p.")
#        if l.startswith("android.permission")
        if l in dangerous_perms:
            print "[DANGEROUS] %s" %lprint
        
        elif l in not3rdparty_perms:
            print "[NOT3PARTY] %s" %lprint
    
        else:
            print "[---------] %s" %lprint
    

    

#danger_perms = [x for x in perms if (x in dangerous_perms)]

# TODO:
TODO = "# objdump --syms"
TODO = "# file"

TOdO = "# Framework detection , .NET, Unity"
TODO = "# TODO: list in which file vulnerable version was found"

TODO=" # DEX SetJavaScriptEnabled , package com.google.android.gms.internal;"

TODO="unzip -q -c Documents\Raccoon\content\apps\com.qihoo.security\com.qihoo.security-2335.apk META-INF/QIHOO360.DSA | openssl pkcs7 -inform DER -print_certs"

TODO="jsoup CVE-2015-6748:"

TODO="jquery 1.4.1 CVE-2015-6748:"

TODO= "JSC"

TODO="Mono"

TODO="""DOT.NET DLL verification, "d:\Program Files\Microsoft SDKs\Windows\v7.1\Bin\peverify"  /verbose  "c:\users\starbuck\appdata\local\temp\scanapkmo03lgapk\assets\bin\Data\Managed\Assembly-CSharp.dll""" 

TODO=""""d:\Program Files\Microsoft SDKs\Windows\v7.1\Bin\ildasm"  /TEXT /METADATA=MDHEADER "c:\users\starbuck\appdata\local\temp\scanapkmo03lgapk\assets\bin\Data\Managed\Assembly-CSharp.dll""" 

TODO="""expat"""

sys.exit(0)

