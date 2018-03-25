import sys

endDocTag = 0x00100101
startTag =  0x00100102
endTag =    0x00100103
textTag=    0x00100104
NULL=0xffffffff

def lew(arr,off):
#    print off, len(arr)
    return ord(arr[off+3])<<24&0xff000000 | ord(arr[off+2])<<16&0xff0000 | ord(arr[off+1])<<8&0xff00 | ord(arr[off])&0xFF

spaces = "                                             ";
def prtIndent( indent,  str):
  return spaces[0:min(indent*2, len(spaces))]+str+"\n"

def compXmlStringAt(arr, strOff):
    strLen=ord(arr[strOff+1])<<8&0xff00|ord(arr[strOff])&0xff
#    print "strlen=%d" % strLen
    chars=""
    for l in range(0,strLen):
        #print l,strOff+2*l*2
        idx = strOff+2+l*2
        if idx < len(arr):
            chars= chars+arr[idx]
        #print chars
#    print "returning:%s" % chars
    return chars

def compXmlString(arr, sitOff, stOff,  strInd):
        if strInd<0 or strInd == 0xffffffff:
            return None

        stroff= stOff+lew(arr,sitOff+strInd*4)
        return compXmlStringAt(arr,stroff)


def printcomment(str):
    return "<!--- %s --> " % str

def decompressxml(xml, withtexttag=False):
    output=""
    numstrings = lew(xml,4*4)
    output=output+printcomment("numstrings=%d" %  numstrings)
    sitOff = 0x24
    stoff = sitOff + numstrings*4
    output=output+printcomment("stoff=%d" %  stoff)
    xmltagoff = lew(xml,12)

    for l in range(xmltagoff,len(xml)-4,4):
        if lew(xml,l) == startTag: # start tag
            xmltagoff = l
            break

    output=output+printcomment("xmltagoff=%d" %  xmltagoff)

    off = xmltagoff
    indent = 0
    starttaglineno=-2

    while off < len(xml):
#        print "off=%d" % off
        tag0 = lew(xml, off)
        lineno = lew(xml,off+2*4)
        namesssi = lew(xml,off+4*4)
        namesi = lew(xml,off+5*4)

        if tag0==startTag:
            tag6 = lew(xml,off+6*4)
            numattrs = lew(xml,off+7*4)
            off = off + 9*4
            name = compXmlString(xml,sitOff,stoff,namesi)
            #print "name=%s" % name
            starttaglineno = lineno
            #print "starttaglineno=%d" % starttaglineno
            #print "numattrs=%s" % numattrs
            sb="" # attributes
            for ii in range(0,numattrs):
                attrnamessi = lew(xml,off)
                attrnamesi=lew(xml,off+4)
                attrvaluesi = lew(xml,off+8)
                attrflags=lew(xml,off+12)
                attrresid=lew(xml,off+16)
                off = off+20
                attrname=compXmlString(xml,sitOff,stoff,attrnamesi)
                attrvalue=""
                #print "attrvaluesi=%s" % attrvaluesi

                if attrvaluesi !=-1 :
                    attrvalue=compXmlString(xml,sitOff,stoff,attrvaluesi)
                else:
                    attrvalue="resuourceid 0x"+hex(attrresid)
                sb = sb+" %s=\"%s\"" % (attrname,attrvalue)
                #print sb

            output=output+prtIndent(indent,"<"+name+sb+">")
            indent=indent+1
        elif tag0==endTag:
            indent=indent-1
            off = off +24
            name=compXmlString(xml,sitOff,stoff,namesi)
            output=output+prtIndent(indent,"</"+name+"><!-- (line %d-%d) -->" %(starttaglineno,lineno))
        elif tag0 == endDocTag:
            break
        elif tag0 == textTag:
            chunksize = lew(xml,off+4)
            lineno=lew(xml,off+8)
            dataid=lew(xml,off+12)
            strsize=lew(xml,off+16)
            cdata=compXmlString(xml,sitOff,stoff,dataid)
            if withtexttag:
                output=output+prtIndent(indent,"<![CDATA[%s]]><!-- dataid=%d -->" % (cdata,dataid))
            #print "text chunk,skipping %d bytes" % chunksize

            off=off+chunksize
        else:
            output=output+printcomment("<!--unreg tag code %d at offset %d - %s-->" % (tag0,off,hex(tag0)))
            break

    output=output+printcomment("end at offset=%d" % off)
    return output

if __name__=='__main__':
    fn = sys.argv[1]
    fp = open(fn,"rb")
    print decompressxml(fp.read())
