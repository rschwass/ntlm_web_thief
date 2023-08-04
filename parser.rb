require 'packetfu'

pcap_file = 'out.pcap'
packets = PacketFu::PcapFile.read_packets pcap_file

packets.each_with_index do |packet, i|
  if packet.payload.match(/NTLM/)
    packet.payload.split("\n").each do |x|
      if x.match(/NTLM/)
        puts x
      end
    end
  end
end
