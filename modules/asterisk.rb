SIP_BASE_REQUEST = "[METHOD] sip:[DST_URI] SIP/2.0\r\n" \
"Via: SIP/2.0/[TRANSPORT] [LOCAL_URI]:[LOCAL_PORT];branch=[BRANCH];rport\r\n" \
"User-Agent: [USERAGENT]\r\n" \
"From: <sip:[LOCAL_ACCOUNT]@[LOCAL_URI]>;tag=[TAG_ID]\r\n" \
"Call-ID: [TAG_ID_CALL]@[LOCAL_URI]\r\n" \
"CSeq: [METHOD_SEQ]\r\n" \
"To: <sip:[DST_ACCOUNT]@[DST_URI]>\r\n" \
"Contact: <sip:[LOCAL_ACCOUNT]@[LOCAL_URI]>;expires=3600\r\n" \
"Accept: application/sdp\r\n" \
"Expires: 3600\r\n" \
"Content-Length: 0\r\n" \
"Max-Forwards: 70\r\n\r\n\r\n"

SIP_METHODS = [
    :OPTIONS    => '1 OPTIONS',
    :REGISTER   => '2 REGISTER'
]

module AsteriskModule
    module_function

    @@module = [
        :name           => 'Asterisk auditing module',
        :author         => 'Federico Fazzi',
        :email          => 'eurialo@deftcode.ninja',
        :version        => '2015.1',
        :description    => "This is a module that manages the services of asterisk        \n" \
                           "\t\t like service identification through the information gathering \n" \
                           "\t\t and enumeration of extensions and many other features."
    ]

    @@services_files = [

        '/etc/asterisk/sip.conf'            => /^(allow=|allowguest=)/,
        '/etc/asterisk/extensions.conf'     => /^(allow=)/
    ]


    @@services_tcp_detect_regex = [
        :identifiers    => /(Server:|User-Agent:)/,
        :methods        => /Allow:/
    ]

    @@services_udp_detect_regex = [
        :identifiers    => /(Server:|User-Agent:)/,
        :methods        => /Allow:/
    ]

    @@devices = []

    @@extensions = []

    def parse_tcp(socket, address, port)

        header = generate_payload(SIP_BASE_REQUEST.dup, [
            :method     => SIP_METHODS.first[:OPTIONS], 
            :extension  => '7002', 
            :address    => address, 
            :port       => port.to_s, 
            :transport  => 'TCP'
        ])

        send_request(socket, 'tcp', header)

        begin
            buf = read_request(socket, 'tcp')

            unless buf.empty?
                if buf.to_s.include?('SIP/')
                    parse_response(address, port, buf, 'tcp')
                    return true
                end
            end

            print "\r"
        rescue Exception
            puts "  + %-16s open port udp/%-15s Unknown\n" % [address, port]
            STDOUT
        end
    end


    def parse_udp(socket, address, port, timeout)

        header = generate_payload(SIP_BASE_REQUEST.dup, [
            :method     => SIP_METHODS.first[:OPTIONS], 
            :extension  => '7001', 
            :address    => address, 
            :port       => port.to_s, 
            :transport  => 'UDP'
        ])

        send_request(socket, 'udp', header)

        begin
            Timeout.timeout(timeout) {
                # Validate the possible sip reply.
                buf = read_request(socket, 'udp')

                if buf.to_s.include?('SIP/')
                    parse_response(address, port, buf, 'udp')
                    return true
                end
            }
        rescue Errno::ECONNREFUSED
            return false
        rescue Timeout::Error
            return false
        end
    end

    # Check for md5 challenge response hash.
    # Try to grep the handshake before sip authentication
    # through REGISTER.
    def parse_password(line, packet_time)
        if line =~ /WWW-Authenticate:/
            puts "  %s: #{GB}handshake request data#{RST}\n  -------------------------------------------" % [packet_time]
            puts "  %s\n" % [line.to_s.gsub(', ', "\r\n  ")]
            return true
        elsif line =~ /Authorization:/
            puts "  %s: #{GB}found an md5 challenge#{RST}\n  -------------------------------------------" % [packet_time]
            puts "  %s\n" % [line.to_s.gsub(', ', "\r\n  ")]
            return true
        end

        return false
    end

    # Enumeration method.
    # Perform extensions enumerations with
    # a custom range.
    def enum(socket, list, address, port, transport, timeout)
        list.each { |e|
            if e.to_s.include?(':~')
                p = e.split(':~').last.chomp
                e = e.split(':~').first.chomp
            else
                p = nil
            end

            print "  #{GB}> testing extension:#{RST} %-22s#{RST}\r" % [e]

            # Generate the payload header.
            header = generate_payload(SIP_BASE_REQUEST.dup, [
                :method     => SIP_METHODS.first[:REGISTER], 
                :extension  => e.to_s, 
                :address    => address, 
                :port       => port.to_s, 
                :transport  => transport.upcase
            ])

            # Check if the socket is alive.
            if socket == nil
                return false
            end

            # Send the udp sip request.
            send_request(socket, transport, header)

            begin
                Timeout.timeout(timeout) {
                    # Validate the possible sip reply.
                    buf = read_request(socket, transport)

                    paddr = address + ':' + port.to_s
                    tmp = []

                    if buf.to_s.include?('200 OK')
                        tmp = [
                            :extension_value    => e.to_s,
                            :extension_address  => address.to_s,
                            :extension_port     => (port.to_s + '/' + transport),
                            :extension_auth     => false,
                            :extension_passwd   => '-'
                        ]

                        puts "  + %-22s extension '#{GB}%s#{RST}' enabled\t[#{GB}no auth#{RST}]" % [paddr, e]
                    elsif buf.to_s.include?('403 Forbidden')
                        tmp = [
                            :extension_value    => e.to_s,
                            :extension_address  => address.to_s,
                            :extension_port     => (port.to_s + '/' + transport),
                            :extension_auth     => true,
                            :extension_passwd   => '-'
                        ]

                        puts "  + %-22s extension '#{GB}%s#{RST}' enabled\t[#{RB}require auth#{RST}]" % [paddr, e]
                    end

                    # Password exists, send a custom authentication payload.
                    unless p.nil?
                        tmp = _exec_authentication(socket, buf, address, port, e, p, header, transport)

                        if tmp == false
                            tmp = []
                        end
                    end

                    unless tmp.empty?
                        @@extensions.push(tmp)
                    end
                }
            rescue Errno::ECONNREFUSED
            rescue Timeout::Error
            end
        }
    end

    # Bruteforce method.
    # Execute extension(s) bruteforce base on 
    # password file list.
    def bruteforce(socket, extension, address, port, passwords, transport, timeout)
        passwords.each { |p|
            if extension.to_s.include?(':~')
                extension = extension.split(':~').first.chomp
            end

            print "  #{GB}> testing authentication: #{RST}%-16s : %-22s#{RST}\r" % [extension, p]

            # Generate the payload header.
            header = generate_payload(SIP_BASE_REQUEST.dup, [
                :method     => SIP_METHODS.first[:REGISTER], 
                :extension  => extension.to_s, 
                :address    => address, 
                :port       => port.to_s, 
                :transport  => transport.upcase
            ])

            # Checks if the socket is alive.
            if socket == nil
                return false
            end

            # Send the udp sip request.
            send_request(socket, transport, header)

            begin
                Timeout.timeout(timeout) {
                    # Validate the possible sip reply.
                    buf = read_request(socket, transport)

                    paddr = address + ':' + port.to_s
                    tmp = []

                    if buf.to_s.include?('WWW-Authenticate')
                        # Validate the possible sip reply.
                        tmp = _exec_authentication(socket, buf, address, port, extension, p, header, transport)

                        unless tmp == false
                            puts "  + %-22s extension #{GB}%-16s#{RST} password:\t#{GB}%-22s#{RST}" % [paddr, extension, p]
                
                            unless tmp.empty?
                                @@extensions.push(tmp)
                            end
                        end
                    elsif buf.to_s.include?('200 OK')
                        tmp = [
                            :extension_value    => extension.to_s,
                            :extension_address  => address.to_s,
                            :extension_port     => (port.to_s + '/' + transport),
                            :extension_auth     => false,
                            :extension_passwd   => '-'
                        ]

                        puts "  + %-22s extension #{GB}%-16s#{RST} password:\t#{GB}-%-22s#{RST}" % [paddr, extension, '']
                    
                        unless tmp.empty?
                            @@extensions.push(tmp)
                        end

                        return true
                    end
                }
            rescue Errno::ECONNREFUSED
            rescue Timeout::Error
            end
        }
    end

    # Execute the authentication request.
    def _exec_authentication(socket, buf, address, port, extension, passwd, header, transport)
        # Get the realm and nonce from response, to generate
        # the md5 challenge that produces the response hash 
        # for sip authentication.
        realm = /realm="(.*)",/.match(buf).to_a.last
        nonce = /nonce="(.*)"/.match(buf).to_a.last

        md5_first = Digest::MD5.new
        md5_first.update(extension.to_s + ':' +  realm.to_s + ':' + passwd.to_s)

        md5_last = Digest::MD5.new
        md5_last.update(SIP_METHODS.first[:REGISTER].split(' ').last + ':sip:' +  address.to_s)

        md5_final = Digest::MD5.new
        md5_final.update(md5_first.hexdigest + ':' + nonce.to_s + ':' + md5_last.hexdigest)

        # Generate authentication string with md5 challenge.
        authenticator = "Authorization: Digest username=\"%s\", " \
        "realm=\"%s\", nonce=\"%s\", opaque=\"\", uri=\"sip:%s\", " \
        "response=\"%s\", algorithm=MD5\r\n" % [
            extension.to_s, 
            realm.to_s, 
            nonce.to_s, 
            address.to_s, 
            md5_final.hexdigest
        ]

        header_auth = ''
        auth_pos = (header.lines.count - 6)

        header.each_line { |hl|
            if auth_pos == 0
                header_auth << authenticator
            end

            header_auth << hl
            auth_pos -= 1
        }

        # Send a new request with authentication.
        send_request(socket, transport, header_auth)

        buf_response = read_request(socket, transport)

        if buf_response.include?('200 OK')
            tmp = [
                :extension_value    => extension.to_s,
                :extension_address  => address.to_s,
                :extension_port     => (port.to_s + '/' + transport),
                :extension_auth     => true,
                :extension_passwd   => passwd.to_s
            ]

            return tmp
        end

        return false
    end