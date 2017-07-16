# frozen_string_literal: true

require 'colorize'

require 'base64'
require 'gsasl'
require 'socket'
require 'net/http'

require 'tsp/packet'

require 'trollop'

module TSP
  class Client
    SERVER = 'broker.aarnet.net.au'

    def initialize
      @sequence = 0

      parse_options
    end

    def my_ip
      Net::HTTP.get(URI('https://api.ipify.org'))
    end

    def parse_options
      actions = %w(create delete info)

      @opts = Trollop.options do
        opt :username, 'username', :type => :string
        opt :password, 'password', :type => :string
        opt :action, actions.join(', '), :type => :string
        opt :ip, 'IP address', :type => :string
      end

      @opts[:ip] ||= my_ip

      Trollop.die :username, 'You must specify a username' unless @opts[:username]
      Trollop.die :action, 'You must specify a password' unless @opts[:password]
      Trollop.die :action, 'You must specify an action' unless @opts[:action]
      Trollop.die :action, "Action must be one of (#{actions.join(', ')})" unless actions.include?(@opts[:action])
    end

    def client
      @client ||=
        begin
          client = UDPSocket.new
          client.connect(SERVER, 3653)
          client
        end
    end

    def run
      send_version
      authenticate

      case @opts[:action]
      when 'create'
        create
        accept
      when 'delete'
        delete
      when 'info'
        info
      else
        abort 'Unknown action'.red
      end
    end

    def next_sequence
      @sequence += 1
    end

    def create_packet(data)
      packet = Packet.new
      packet.data = data
      packet.sequence = next_sequence

      packet.to_binary_s
    end

    def send_version
      packet = create_packet('VERSION=2.0.1')
      client.send(packet, 0)
      response = client.recv(65_507) # Max UDP Packet size
      packet = Packet.read(response)

      return if packet.data == 'CAPABILITY TUNNEL=V6V4 TUNNEL=V6UDPV4 AUTH=DIGEST-MD5'

      abort "Version Error: #{packet.data}".red
    end

    # rubocop:disable Metrics/AbcSize,Metrics/MethodLength
    def authenticate
      packet = create_packet('AUTHENTICATE DIGEST-MD5')
      client.send(packet, 0)

      context = Gsasl::Context.new
      sasl = context.create_client('DIGEST-MD5')
      sasl.credentials!(@opts[:username], @opts[:password])
      sasl.service!('tsp', 'hexos')

      sasl.authenticate_with do |remote|
        remote.receive do
          response = client.recv(65_507)
          packet = Packet.read(response + "\n") # Full footer is missing
          data = Base64.decode64(packet.data)
          data.gsub!(/utf8/, 'utf-8')
          Base64.strict_encode64(data)
        end

        remote.send do |data|
          line = Base64.decode64(data)
          line.gsub!(/, /, ',')
          line = Base64.strict_encode64(line)
          line += "\r\n" if line.size.positive?
          packet = create_packet(line)
          client.send(packet, 0)
        end
      end
      sasl.close

      response = client.recv(65_507) # Max UDP Packet size
      packet = Packet.read(response)

      return if packet.data == '200 Success'

      abort "Authentication Error: #{packet.data}".red
    end
    # rubocop:enable Metrics/AbcSize,Metrics/MethodLength

    def create
      xml = <<~EOS
      <tunnel action="create" type="v6anyv4" proxy="yes">
        <client>
          <address type="ipv4">#{@opts[:ip]}</address>
          <router>
            <prefix length="64"/>
          </router>
        </client>
      </tunnel>
      EOS

      send_xml('create', xml)
    end

    def accept
      xml = '<tunnel action="accept"></tunnel>'

      send_xml('accept', xml)
    end

    def info
      xml = <<~EOS
      <tunnel action="info" type="v6anyv4">
      </tunnel>
      EOS

      send_xml('info', xml)
    end

    def delete
      xml = '<tunnel action="delete"></tunnel>'

      send_xml('delete', xml)
    end

    def send_xml(action, xml)
      length = xml.size + 2

      packet = create_packet("Content-length: #{length}\r\n#{xml}")
      client.send(packet, 0)

      response = client.recv(65_507) # Max UDP Packet size
      packet = Packet.read(response)
      _, status, xml = packet.data.split("\r\n")

      puts xml if xml

      return if status == '200 Success'

      abort "#{action.capitalize} Error: #{status}".red
    end
  end
end
