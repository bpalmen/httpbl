# The Httpbl middleware 

class HttpBL
  autoload :Resolv, 'resolv'
  
  def initialize(app, options = {})
    @app = app
    @options = {:blocked_search_engines => [],
                :age_threshold => 10,
                :threat_level_threshold => 2,
                :deny_types => [1, 2, 4, 8, 16, 32, 64, 128]
                # 8..128 aren't used as of 3/2009, but might be used in the future
                }.merge(options)
    raise "Missing :api_key for Http:BL middleware" unless @options[:api_key]
  end
  
  def call(env)
    dup._call(env)
  end
  
  def _call(env)
    ip = Rack::Request.new(env).ip
    query = @options[:api_key] + '.' + ip.split('.').reverse.join('.') + '.dnsbl.httpbl.org'
    @bl_response = (Resolv::DNS.new.getaddress(query).to_s rescue nil)
    if @bl_response and blocked?(@bl_response)
      [403, {"Content-Type" => "text/html"}, "<h1>403 Forbidden</h1> Request IP is listed as suspicious by <a href='http://projecthoneypot.org/ip_#{ip}'>Project Honeypot</a>"]
    else
      @app.call(env)
    end
  end
  
  def blocked?(response)
    response = response.split('.').collect!(&:to_i)
    if response[0] == 127 
      if response[3] == 0
        @blocked = true if @options[:blocked_search_engines].include? response[2]
      else 
        @age = true if response[1] < @options[:age_threshold]
        @threat = true if response[2] > @options[:threat_level_threshold]
        @options[:deny_types].each do |key|
          @deny = true if response[3] & key == key  
        end
        @blocked = true if @deny and @threat and @age
      end
    end
    return @blocked
  end

end