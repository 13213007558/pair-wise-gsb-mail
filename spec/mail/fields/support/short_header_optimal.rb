# encoding: utf-8
# frozen_string_literal: true
require 'base64'
require 'mail'

# Independent exhaustive optimizer for a short unstructured UTF-8 header
# value. Legality is judged by round-tripping through the gem's own decoder
# (RFC 2047 §6.2 whitespace rules), plus line/encoded-word length limits.
module ShortHeaderOptimal
  QP = ("!".b.."~".b).to_a.join.b; QP.delete!("=?_"); QPB = QP.bytes.to_a
  def self.qw(p)
    t=''.b
    p.each_byte { |c| c==0x20 ? t<<'_' : QPB.include?(c) ? t<<c : (t<<'='<<('%02X'%c)) }
    "=?UTF-8?Q?#{t}?=".b
  end
  def self.bw(p); "=?UTF-8?B?#{Base64.strict_encode64(p)}?=".b; end
  def self.u8len(c); c<0xE0 ? 2 : c<0xF0 ? 3 : c<0xF8 ? 4 : 1; end
  def self.ctrl?(c); (c<0x20 && c!=0x09) || c==0x7F; end
  def self.wsp?(c); c==0x20||c==0x09; end
  def self.force?(p)
    p.each_byte.any? { |c| c>=0x80||ctrl?(c) } || p.include?('=?'.b)
  end

  # [kind,start,len]
  def self.units(s)
    b=s.b; u=[]; i=0
    while i<b.bytesize
      c=b.getbyte(i)
      if c==0x20||c==0x09 then u<<[:wsp,i,1]; i+=1
      elsif ctrl?(c)
        st=i; i+=1
        i+=1 while i<b.bytesize && ctrl?(b.getbyte(i))
        u<<[:force,st,i-st]
      elsif c>=0x80
        st=i; i+=u8len(c)
        i+=1 while i<b.bytesize && ctrl?(b.getbyte(i))
        u<<[:force,st,i-st]
      else
        j=i
        loop do
          break if j>=b.bytesize
          x=b.getbyte(j)
          break unless x>0x20 && x<0x7F
          break if x==0x3D && j+1<b.bytesize && b.getbyte(j+1)==0x3F
          j+=1
        end
        u<<[:word,i,j-i] if j>i
        if j<b.bytesize && b.getbyte(j)==0x3D && j+1<b.bytesize && b.getbyte(j+1)==0x3F
          st=j; j+=2
          j+=1 while j<b.bytesize && ctrl?(b.getbyte(j))
          u<<[:force,st,j-st]
        end
        i=j
      end
    end
    [u,b]
  end

  def self.atoms(u,raw,i,off,prev,acc,out)
    if i>=u.length then out<<acc; return end
    kind,base,len=u[i]
    if kind==:word
      remaining = raw.byteslice(base+off, len-off)
      # The whole suffix stays plain.
      atoms(u,raw,i+1,0,:plain,acc+[[:plain,remaining]],out)
      # Or an encoded-word begins at some byte boundary inside this run:
      # emit the plain prefix before it (0..k bytes) and then the EW.
      (0...(len-off)).each do |k|
        prefix_acc = acc
        prefix_acc = acc + [[:plain, raw.byteslice(base+off, k)]] if k > 0
        prev = k > 0 ? :plain : prev
        ew(u,raw,i,off+k,prev,''.b,prefix_acc,out,true)
      end
    elsif kind==:wsp
      atoms(u,raw,i+1,0,:plain,acc+[[:plain,raw.byteslice(base,1)]],out)
      ew(u,raw,i,0,prev,''.b,acc,out,true)
    else
      ew(u,raw,i,0,prev,''.b,acc,out,true)
    end
  end

  def self.ew(u,raw,i,off,prev,payload,acc,out,contact)
    return if i>=u.length
    kind,base,len=u[i]
    if kind==:word
      rem=len-off
      (1..rem).each do |k|
        p=payload+raw.byteslice(base+off,k)
        next if wsp?(p.getbyte(0)) && prev!=:start && payload.empty?
        next if wsp?(p.getbyte(-1))
        ni = off+k==len ? i+1 : i
        no = off+k==len ? 0 : off+k
        emit_ew(u,raw,ni,no,p,prev,acc,out,true)
      end
      full=payload+raw.byteslice(base+off,rem)
      # Continue even when this WORD ends in WSP: a following FORCE unit may
      # complete the encoded-word (the WSP becomes interior whitespace).
      ew(u,raw,i+1,0,prev,full,acc,out,contact)
    elsif kind==:wsp
      p=payload+raw.byteslice(base,1)
      return if wsp?(p.getbyte(0)) && prev!=:start && payload.empty?
      ew(u,raw,i+1,0,prev,p,acc,out,contact)
    else
      p=payload+raw.byteslice(base,len)
      emit_ew(u,raw,i+1,0,p,prev,acc,out,contact)
      ew(u,raw,i+1,0,prev,p,acc,out,contact)
    end
  end

  def self.emit_ew(u,raw,ni,no,payload,prev,acc,out,contact)
    return unless force?(payload)
    return if prev==:plain && !contact
    return if wsp?(payload.getbyte(-1))
    return if wsp?(payload.getbyte(0)) && prev!=:start
    q=qw(payload); b=(payload.bytesize<=45 ? bw(payload) : nil)
    [q,b].compact.each do |w|
      next if w.bytesize>75
      atoms(u,raw,ni,no,:ew,acc+[[:ew,w]],out)
    end
  end

  def self.layouts(al,fc,ll)
    out=[]
    rec=lambda do |i,body,col,first,prev|
      if i==al.length then out<<body; return end
      type,text=al[i]; cap=first ? fc : ll
      if type==:plain
        rec.call(i+1,body+text,col+text.bytesize,false,:plain) if col+text.bytesize<=cap
        rec.call(i+1,body+"\r\n ".b+text,1+text.bytesize,false,:plain) if prev && 1+text.bytesize<=ll
      else
        if prev.nil?
          rec.call(i+1,body+text,col+text.bytesize,false,:ew) if col+text.bytesize<=cap
        elsif prev==:ew
          rec.call(i+1,body+' '.b+text,col+1+text.bytesize,false,:ew) if col+1+text.bytesize<=cap
          rec.call(i+1,body+"\r\n ".b+text,1+text.bytesize,false,:ew) if 1+text.bytesize<=ll
        else
          rec.call(i+1,body+text,col+text.bytesize,false,:ew) if col+text.bytesize<=cap
        end
      end
    end
    rec.call(0,''.b,0,true,nil)
    out
  end

  def self.optimal(s,field='Subject',ll=78)
    u,raw=units(s)
    lists=[]; atoms(u,raw,0,0,:start,[],lists); lists.uniq!
    fc=ll-(field+': ').length
    target=s.b; best=nil; seen={}
    lists.each do |al|
      next if al.any? { |t,x| t==:plain && x.each_byte.any? { |c| c!=0x20&&c!=0x09&&(c<0x20||c>126) } }
      layouts(al,fc,ll).each do |body|
        next if seen[body]; seen[body]=true
        # Judge legality through the real header parser: leading/trailing
        # whitespace is stripped there exactly as it would be in practice,
        # and folding/encoded-word whitespace rules apply.
        hdr=field+': '+body
        dec=(Mail::Header.new(hdr)[field].decoded.to_s.b rescue nil)
        next unless dec==target
        next unless body.lines.all? { |ln| ln.chomp.bytesize<=ll }
        best=body if best.nil?||body.bytesize<best.bytesize||(body.bytesize==best.bytesize&&body<best)
      end
    end
    best
  end
end
