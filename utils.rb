def html_get_hash(arg = {}, challenge)
    ntlm_ver = arg[:ntlm_ver]
    if ntlm_ver == NTLM_CONST::NTLM_V1_RESPONSE or ntlm_ver == NTLM_CONST::NTLM_2_SESSION_RESPONSE
      lm_hash = arg[:lm_hash]
      nt_hash = arg[:nt_hash]
    else
      lm_hash = arg[:lm_hash]
      nt_hash = arg[:nt_hash]
      lm_cli_challenge = arg[:lm_cli_challenge]
      nt_cli_challenge = arg[:nt_cli_challenge]
    end
    domain = arg[:domain]
    user = arg[:user]
    host = arg[:host]
    ip = arg[:ip]
    
    unless @previous_lm_hash == lm_hash and @previous_ntlm_hash == nt_hash then

      @previous_lm_hash = lm_hash
      @previous_ntlm_hash = nt_hash

      # Check if we have default values (empty pwd, null hashes, ...) and adjust the on-screen messages correctly
      case ntlm_ver
      when NTLM_CONST::NTLM_V1_RESPONSE
        if NTLM_CRYPT::is_hash_from_empty_pwd?({:hash => [nt_hash].pack("H*"),:srv_challenge => challenge,
                :ntlm_ver => NTLM_CONST::NTLM_V1_RESPONSE, :type => 'ntlm' })
          puts("NLMv1 Hash correspond to an empty password, ignoring ... ")
          return
        end
        if (lm_hash == nt_hash or lm_hash == "" or lm_hash =~ /^0*$/ ) then
          lm_hash_message = "Disabled"
        elsif NTLM_CRYPT::is_hash_from_empty_pwd?({:hash => [lm_hash].pack("H*"),:srv_challenge => challenge,
                :ntlm_ver => NTLM_CONST::NTLM_V1_RESPONSE, :type => 'lm' })
          lm_hash_message = "Disabled (from empty password)"
        else
          lm_hash_message = lm_hash
          lm_chall_message = lm_cli_challenge
        end
      when NTLM_CONST::NTLM_V2_RESPONSE
        if NTLM_CRYPT::is_hash_from_empty_pwd?({:hash => [nt_hash].pack("H*"),:srv_challenge => challenge,
                :cli_challenge => [nt_cli_challenge].pack("H*"),
                :user => Rex::Text::to_ascii(user),
                :domain => Rex::Text::to_ascii(domain),
                :ntlm_ver => NTLM_CONST::NTLM_V2_RESPONSE, :type => 'ntlm' })
          puts("NTLMv2 Hash correspond to an empty password, ignoring ... ")
          return
        end
        if lm_hash == '0' * 32 and lm_cli_challenge == '0' * 16
          lm_hash_message = "Disabled"
          lm_chall_message = 'Disabled'
          #puts challenge
        elsif NTLM_CRYPT::is_hash_from_empty_pwd?({:hash => [lm_hash].pack("H*"),:srv_challenge => challenge,
                :cli_challenge => [lm_cli_challenge].pack("H*"),
                :user => Rex::Text::to_ascii(user),
                :domain => Rex::Text::to_ascii(domain),
                :ntlm_ver => NTLM_CONST::NTLM_V2_RESPONSE, :type => 'lm' })
          lm_hash_message = "Disabled (from empty password)"
          lm_chall_message = 'Disabled'
        else
          lm_hash_message = lm_hash
          lm_chall_message = lm_cli_challenge
        end

      when NTLM_CONST::NTLM_2_SESSION_RESPONSE
        if NTLM_CRYPT::is_hash_from_empty_pwd?({:hash => [nt_hash].pack("H*"),:srv_challenge => challenge,
                :cli_challenge => [lm_hash].pack("H*")[0,8],
                :ntlm_ver => NTLM_CONST::NTLM_2_SESSION_RESPONSE, :type => 'ntlm' })
          puts("NTLM2_session Hash correspond to an empty password, ignoring ... ")
          return
        end
        lm_hash_message = lm_hash
        lm_chall_message = lm_cli_challenge
      end

      # Display messages
      domain = Rex::Text::to_ascii(domain)
      user = Rex::Text::to_ascii(user)

        case ntlm_ver
        when NTLM_CONST::NTLM_V1_RESPONSE, NTLM_CONST::NTLM_2_SESSION_RESPONSE

          
          puts(
            [
              user,"",
              domain ? domain : "NULL",
              lm_hash ? lm_hash : "0" * 48,
              nt_hash ? nt_hash : "0" * 48,
              challenge.unpack("H*")[0]
            ].join(":").gsub(/\n/, "\\n")
          )
        when NTLM_CONST::NTLM_V2_RESPONSE
          puts "lmv2"
           puts(
            [
              user,"",
              domain ? domain : "NULL",
              challenge.unpack("H*")[0],
              lm_hash ? lm_hash : "0" * 32,
              lm_cli_challenge ? lm_cli_challenge : "0" * 16
            ].join(":").gsub(/\n/, "\\n")
          )
          puts "ntlmv2"
          puts(
            [
              user,"",
              domain ? domain : "NULL",
              challenge.unpack("H*")[0],
              nt_hash ? nt_hash : "0" * 32,
              nt_cli_challenge ? nt_cli_challenge : "0" * 160
            ].join(":").gsub(/\n/, "\\n")
          )
        end

    end
end


  def process_hash(hash, challenge, remote_ip = '127.0.0.1')
    
    domain,user,host,lm_hash,ntlm_hash = MESSAGE.process_type3_message(hash)
        nt_len = ntlm_hash.length
  
        if nt_len == 48 #lmv1/ntlmv1 or ntlm2_session
          arg = { :ntlm_ver => NTLM_CONST::NTLM_V1_RESPONSE,
            :lm_hash => lm_hash,
            :nt_hash => ntlm_hash
          }
  
          if arg[:lm_hash][16,32] == '0' * 32
            arg[:ntlm_ver] = NTLM_CONST::NTLM_2_SESSION_RESPONSE
          end
        # if the length of the ntlm response is not 24 then it will be bigger and represent
        # a ntlmv2 response
        elsif nt_len > 48 #lmv2/ntlmv2
          arg = { :ntlm_ver   => NTLM_CONST::NTLM_V2_RESPONSE,
            :lm_hash   => lm_hash[0, 32],
            :lm_cli_challenge  => lm_hash[32, 16],
            :nt_hash   => ntlm_hash[0, 32],
            :nt_cli_challenge  => ntlm_hash[32, nt_len  - 32]
          }
        elsif nt_len == 0
          puts("Empty hash from #{host} captured, ignoring ... ")
        else
          puts("Unknown hash type from #{host}, ignoring ...")
        end
  
        # If we get an empty hash, or unknown hash type, arg is not set.
        # So why try to read from it?
        if not arg.nil?
          arg[:host] = host
          arg[:user] = user
          arg[:domain] = domain
          arg[:ip] = remote_ip
          html_get_hash(arg, challenge)
        end
  

  end


  def parse_type1_domain(message)
    domain = nil
    workstation = nil

    reqflags = message[12,4]
    reqflags = reqflags.unpack("V").first

    if((reqflags & NTLM_CONST::NEGOTIATE_DOMAIN) == NTLM_CONST::NEGOTIATE_DOMAIN)
      dom_len = message[16,2].unpack('v')[0].to_i
      dom_off = message[20,2].unpack('v')[0].to_i
      domain = message[dom_off,dom_len].to_s
    end
    if((reqflags & NTLM_CONST::NEGOTIATE_WORKSTATION) == NTLM_CONST::NEGOTIATE_WORKSTATION)
      wor_len = message[24,2].unpack('v')[0].to_i
      wor_off = message[28,2].unpack('v')[0].to_i
      workstation = message[wor_off,wor_len].to_s
    end
    return domain,workstation

  end
